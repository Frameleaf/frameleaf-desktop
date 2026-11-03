"""Qualify and assemble an unsigned Windows x64 host; no signing, installation or publication."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import tarfile
import zipfile

from bind_host_raw import read_receipt
from build_host_bundle import assemble, host_entries
from build_host_database_windows import qualify as qualify_database
from build_host_ffmpeg import qualify as qualify_media, unpack
from build_host_geodata import build as build_geodata
from build_host_server import stage_server
from build_host_windows_support import build as build_support, NODE_EXE_SHA
from build_runtime import BuildError, build_environment, git_blob, inventory, regular, run, sha256
from obtain_windows_host_components import obtain as obtain_components, SOURCE_REVISION
from source_archive import verify_source_archive
from windows_private_directory import create_private_directory

ROOT = Path(__file__).resolve().parent.parent
STUDIO_CHECK = '''
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
assert.equal(process.platform, 'win32');
assert.equal(process.version, 'v26.11.1');
const runtime = process.argv[1];
const { createEngineRenderer } = await import(pathToFileURL(join(runtime, 'studio/tools/bundled-worker-renderer.mjs')));
const signal = AbortSignal.timeout(600000);
const renderer = await createEngineRenderer({ ffmpeg: process.env.FFMPEG_PATH, ffprobe: process.env.FFPROBE_PATH, signal });
const result = await renderer.conformance({ signal });
assert.ok(result.formats.includes('mp4-h264'), 'Private sandboxed Studio must write and read back H.264/AAC MP4');
console.log(JSON.stringify({ qualification:'passed', ...result, installedPlatformQualified:false, fullMediaConformance:false }));
'''


def build(source: Path, approvals: dict, output: Path, epoch: int) -> None:
    policy = read_receipt(ROOT / 'runtime/release-trust.json')
    if (type(epoch) is not int or not policy['minimumRuntimeEpoch'] <= epoch < 2**64
            or any(not p.is_absolute() or p.resolve() != p for p in [source, output])
            or output.exists() or output.is_symlink() or output.is_relative_to(source)
            or source.is_relative_to(output)
            or not stat.S_ISDIR(regular(source).st_mode)
            or not stat.S_ISDIR(regular(output.parent).st_mode)):
        raise BuildError('host_windows_assembly_inputs_invalid')
    if platform.system() != 'Windows' or platform.machine() not in {'AMD64', 'x86_64'}:
        raise BuildError('host_windows_assembly_target_unsupported')
    git = shutil.which('git')
    if not git:
        raise BuildError('host_windows_assembly_git_missing')
    create_private_directory(output)
    work, evidence, candidate = output / 'work', output / 'evidence', output / 'candidate'
    create_private_directory(work)
    create_private_directory(evidence)
    report = {'schemaVersion':1, 'sourceRevision':SOURCE_REVISION, 'epoch':epoch,
              'qualification':'failed', 'runtimeQualified':False, 'redistributable':False,
              'installedPlatformQualified':False, 'fullMediaConformance':False,
              'signaturePresent':False, 'consumers':{}}
    receipt = output / 'qualification.json'
    receipt.write_text(json.dumps(report) + '\n', encoding='utf-8')
    partial = output / 'qualification.json.part'
    try:
        env = build_environment(work, os.environ)
        env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1', GIT_NO_REPLACE_OBJECTS='1')
        inputs = work / 'components'
        obtain_components(source, approvals, inputs)
        staged = read_receipt(inputs / 'qualification.json')
        if staged.get('qualification') != 'passed':
            raise BuildError('host_windows_assembly_components_unqualified')
        roots = {role: inputs / record['root'] for role, record in staged['components'].items()}
        assets = roots['assets']
        shutil.copy2(inputs / 'qualification.json', evidence / 'components.json')
        for role, root in roots.items():
            target = evidence / 'source-components' / role
            target.mkdir(parents=True)
            shutil.copy2(inputs / 'inputs' / role / 'producer.json', target / 'producer.json')
            for name in (['manifest.json', 'manifest.sig'] if role == 'ml' else
                         ['server-qualification.json','metadata-qualification.json','qualification.json'] if role == 'server' else
                         [] if role == 'assets' else ['qualification.json']):
                shutil.copy2(root / name, target / name)
        for role in ['web','plugin','studio']:
            shutil.copy2(assets / role / 'qualification.json', evidence / ('source-' + role + '.json'))

        host = inputs / 'bound-server-raw'
        binding = read_receipt(host / 'qualification.json')
        shutil.copy2(host / 'qualification.json', evidence / 'server-raw-binding.json')
        shutil.rmtree(host / 'work')
        support, geodata = work / 'support', work / 'geodata'
        build_support(source, SOURCE_REVISION, assets / 'studio/studio-worker/studio', support)
        build_geodata(source, SOURCE_REVISION, geodata)
        for name, root, payload in [('support',support,'support'),('geodata',geodata,'geodata')]:
            checked = read_receipt(root / 'qualification.json')
            if (checked.get('qualification') != 'passed' or checked.get('sourceRevision') != SOURCE_REVISION
                    or checked.get('files') != inventory(root / payload)):
                raise BuildError('host_windows_assembly_static_input_changed:' + name)
            shutil.copy2(root / 'qualification.json', evidence / (name + '.json'))
        (host / 'build/plugins').mkdir(parents=True)
        for source_root, destination in [
            (roots['database']/'postgres','pg'), (roots['hdr']/'media','media'),
            (roots['media']/'media','media-tools'), (assets/'web/www','build/www'),
            (assets/'plugin/plugin','build/plugins/immich-plugin-core'),
            (assets/'studio/studio-worker/studio','studio'),
            (assets/'studio/studio-worker/fonts','fonts'),
            (support/'support/browser','browser'), (geodata/'geodata','build/geodata'),
        ]:
            stage_server(source_root, host / destination)
        shutil.copy2(support / 'support/node/node.exe', host / 'node.exe')
        licenses = host / 'licenses'
        licenses.mkdir()
        shutil.copy2(support / 'support/node/LICENSE', licenses / 'Node-LICENSE')
        shutil.copy2(assets / 'studio/studio-worker/LICENSE', licenses / 'Studio-LICENSE')
        (licenses / 'Frameleaf-LICENSE').write_bytes(git_blob(git, source, SOURCE_REVISION, 'LICENSE', env))
        node = host / 'node.exe'
        if sha256(node) != NODE_EXE_SHA or run([node,'--version'],cwd=work,env=env) != 'v26.11.1':
            raise BuildError('host_windows_assembly_node_changed')
        before = inventory(host)
        before.pop('qualification.json')
        metadata = read_receipt(roots['server'] / 'qualification.json')
        derived = {**binding, **{key:metadata[key] for key in [
            'adaptedModuleSha256','originalModuleSha256','vendorVersion','executableVendorVersion']},
            'stagedFiles':before, 'componentSetReceiptSha256':sha256(inputs/'qualification.json'),
            'runtimeQualified':False, 'redistributable':False,
            'scope':'Derived authoring input for current consumers; original receipts retained separately'}
        (host / 'qualification.json').write_text(json.dumps(derived),encoding='utf-8',newline='\n')
        environment_script = f'''import {{ hostEnvironment }} from {json.dumps((ROOT/'runtime/host-agent.mjs').as_uri())};
console.log(JSON.stringify(hostEnvironment({{runtime:process.argv[1],state:process.argv[2],entryPoints:JSON.parse(process.argv[3])}})));'''
        env.update(json.loads(run([node,'--input-type=module','--eval',environment_script,host,work,
                                   json.dumps(host_entries())],cwd=work,env=env)))
        env['FRAMELEAF_HDR_BINDING'] = str(host / 'media/image-hdr.node')
        env['OMP_THREAD_LIMIT'] = '1'
        consumers = work / 'consumers'
        consumers.mkdir()
        for name in ['database','media']:
            (consumers / name).mkdir()
        # Native policy belongs to this desktop recipe; --source selects the application Dockerfile.
        database = read_receipt(ROOT/'runtime/host-database.json')
        report['databaseCertified'] = database['certified']
        env['FRAMELEAF_BUILD_ERROR_LOG'] = str(evidence/'native-consumer-error.log')
        report['consumers']['database'] = {'qualification':'passed','checks':qualify_database(host/'pg',consumers/'database',database,env)}
        report['consumers']['media'] = qualify_media(host/'media-tools/ffmpeg.exe',host/'media-tools/ffprobe.exe',consumers/'media',env)
        for role, script, extra in [('raw','qualify_host_raw.mjs',[roots['raw']]),
                                    ('metadata','qualify_host_exiftool.mjs',[]),
                                    ('plugin','qualify_host_plugin.mjs',[assets/'plugin'])]:
            result = json.loads(run([node,ROOT/'tools'/script,host,*extra],cwd=work,env=env))
            if result.get('qualification') != 'passed' or result.get('sourceRevision') != SOURCE_REVISION:
                raise BuildError('host_windows_assembly_consumer_failed:' + role)
            if role == 'metadata' and result.get('componentReceiptSha256') != sha256(host/'qualification.json'):
                raise BuildError('host_windows_assembly_metadata_binding_changed')
            report['consumers'][role] = result
        snapshot, archive = work/'current-source', work/'current-source.tar'
        snapshot.mkdir()
        paths = ['server/test/native']
        run([git,'-c','core.autocrlf=false','-c','core.eol=lf','archive','--format=tar','--output',archive,SOURCE_REVISION,*paths],cwd=source,env=env)
        verify_source_archive(git,source,SOURCE_REVISION,paths,archive,env)
        unpack(archive,snapshot)
        hdr = run([node,'--test',snapshot/'server/test/native/image-hdr.test.mjs'],cwd=work,
                  env={**env,'FRAMELEAF_HDR_ISO_TEST':'1'})
        (evidence/'hdr-current-fixtures.tap').write_text(hdr+'\n',encoding='utf-8')
        report['consumers']['hdr'] = {'qualification':'passed','sourceRevision':SOURCE_REVISION,
                                     'fixtureOutputSha256':sha256(evidence/'hdr-current-fixtures.tap')}
        report['consumers']['studio'] = json.loads(run([node,'--input-type=module','--eval',STUDIO_CHECK,host],cwd=work,env=env))
        if any(result.get('qualification') != 'passed' for result in report['consumers'].values()):
            raise BuildError('host_windows_assembly_consumer_failed')
        after = inventory(host)
        after.pop('qualification.json')
        if after != before:
            raise BuildError('host_windows_assembly_payload_changed_during_consumers')
        shutil.copy2(host/'qualification.json',evidence/'current-consumer-input.json')
        (evidence/'current-consumers.json').write_text(json.dumps(report['consumers'],indent=2)+'\n',encoding='utf-8')
        # This existing assembler verifies the nested ML signature and inventory before and after copying.
        assemble(host,roots['ml'],roots['manager']/'manager',roots['backup']/'backup',candidate,SOURCE_REVISION,epoch)
        shutil.rmtree(candidate/'work')
        report['candidate'] = read_receipt(candidate/'qualification.json')
        report['manifestSha256'] = sha256(candidate/'manifest.json')
        shutil.rmtree(work)
        report['qualification'] = 'passed'
        report['scope'] = 'Current component consumers and complete unsigned host inventory; no installed-host, signing or release acceptance'
        partial.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
        partial.replace(receipt)
    except (Exception, KeyboardInterrupt):
        # Both contain executable or private fixture data; attempt both removals even if one fails.
        try:
            if work.exists(): shutil.rmtree(work)
        finally:
            try:
                if candidate.exists(): shutil.rmtree(candidate)
            finally:
                partial.unlink(missing_ok=True)
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source','approvals','output']:
        parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--epoch',required=True,type=int)
    args = parser.parse_args()
    try:
        info = regular(args.approvals)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 16*1024:
            raise BuildError('host_windows_assembly_approval_invalid')
        build(args.source,json.loads(args.approvals.read_text(encoding='utf-8-sig')),args.output,args.epoch)
    except (BuildError,OSError,ValueError,KeyError,subprocess.SubprocessError,tarfile.TarError,zipfile.BadZipFile) as error:
        parser.exit(1,str(error) if isinstance(error,BuildError) else 'host_windows_assembly_failed')
