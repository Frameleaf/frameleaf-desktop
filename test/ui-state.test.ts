import { test } from 'node:test';
import assert from 'node:assert/strict';
import { formatUsd, formatMicroUsd, formatUsdShort, formatBytes, percent, relativeTime, formatWhen, countdown, initials, hostOf, connectionPath, pathIndicator, mergeServers, platformClass, workloadPill, workerTone, fingerprintShort } from '../src/ui-state.ts';
import type { CloudServer, DiscoveredServer } from '../src/server-types.ts';

test('money renders USD doubles and micro-USD integers without ever printing NaN', () => {
  assert.equal(formatUsd(31.4), '$31.40');
  assert.equal(formatUsd(0), '$0.00');
  assert.equal(formatUsd(-0.001), '$0.00');
  assert.equal(formatUsd(-2.5), '−$2.50');
  assert.equal(formatUsd('12.6'), '$12.60');
  assert.equal(formatUsd(1234.5), '$1,234.50');
  for (const bad of [null, undefined, Number.NaN, Number.POSITIVE_INFINITY, 'abc', {}, []]) assert.equal(formatUsd(bad), '—');
  assert.equal(formatMicroUsd(2_100_000), '$2.10');
  assert.equal(formatMicroUsd(33_500_000n), '$33.50');
  assert.equal(formatMicroUsd('25000000'), '$25.00');
  assert.equal(formatMicroUsd(undefined), '—');
  assert.equal(formatUsdShort(20), '$20');
  assert.equal(formatUsdShort(12.5), '$12.50');
});

test('bytes use decimal units like the server storage report', () => {
  assert.equal(formatBytes(0), '0 bytes');
  assert.equal(formatBytes(1), '1 byte');
  assert.equal(formatBytes(999), '999 bytes');
  assert.equal(formatBytes(1_500), '1.5 kB');
  assert.equal(formatBytes(11_600_000_000), '11.6 GB');
  assert.equal(formatBytes(38_000_000_000), '38 GB');
  assert.equal(formatBytes(640_000_000_000), '640 GB');
  assert.equal(formatBytes(1_000_000_000_000), '1 TB');
  assert.equal(formatBytes(-5), '—');
  assert.equal(formatBytes('x'), '—');
  assert.equal(percent(42e9, 200e9), 21);
  assert.equal(percent(5, 0), 0);
  assert.equal(percent(300, 100), 100);
});

test('relative and absolute times read naturally and never throw on bad input', () => {
  const now = Date.UTC(2026, 10, 3, 10, 44);
  assert.equal(relativeTime(now - 10_000, now), 'just now');
  assert.equal(relativeTime(now - 2 * 60_000, now), '2 minutes ago');
  assert.equal(relativeTime(new Date(now - 3 * 86_400_000).toISOString(), now), '3 days ago');
  assert.equal(relativeTime(now + 4 * 3_600_000, now), 'in 4 hours');
  assert.equal(relativeTime(null, now), 'never');
  assert.equal(relativeTime('not a date', now), 'never');
  assert.match(formatWhen(now - 60_000, now), /^Today, /);
  assert.match(formatWhen(now - 86_400_000, now), /^Yesterday, /);
  assert.match(formatWhen(Date.UTC(2026, 10, 1, 2, 0), now), /^Nov 1, /);
  assert.equal(formatWhen(undefined, now), '—');
  assert.equal(countdown(now + 272_000, now), '4:32');
  assert.equal(countdown(now - 1, now), '0:00');
});

test('initials and hosts are derived defensively', () => {
  assert.equal(initials('AJ'), 'AJ');
  assert.equal(initials('Ada Lovelace'), 'AL');
  assert.equal(initials('aj@heroit.ca'), 'AH');
  assert.equal(initials(''), '?');
  assert.equal(initials(null), '?');
  assert.equal(hostOf('https://photos.home.example/'), 'photos.home.example');
  assert.equal(hostOf('https://tower.local:2283'), 'tower.local:2283');
  assert.equal(hostOf('tower.local'), 'tower.local');
  assert.equal(hostOf(null), '');
  assert.equal(fingerprintShort('3a91ab12cd34c07e'), '3A91…C07E');
  assert.equal(fingerprintShort(null), '');
});

test('connection paths are labelled and only the signed-in candidate is marked current', () => {
  const connections = { instanceId: 'k7', publicUrl: 'https://photos.ajhome.ca', connections: [
    { kind: 'local', uri: 'https://192-168-1-10.k7.frameleaf.net', protocol: 'https', address: '192.168.1.10', port: 2283, local: true, relay: false, ipv6: false, custom: false, dnsRebindingProtection: true, httpsRequired: true, verified: true },
    { kind: 'wan', uri: 'https://70-51-18-204.k7.frameleaf.net:2443', protocol: 'https', address: '70.51.18.204', port: 2443, local: false, relay: false, ipv6: false, custom: false, dnsRebindingProtection: true, httpsRequired: true, verified: true },
    { kind: 'wan', uri: 'https://photos.ajhome.ca', protocol: 'https', address: 'photos.ajhome.ca', port: 443, local: false, relay: true, ipv6: false, custom: true, dnsRebindingProtection: true, httpsRequired: true, verified: false },
    { kind: 'relay', uri: 'https://r.k7.frameleaf.net', protocol: 'https', address: 'r.k7.frameleaf.net', port: 443, local: false, relay: true, ipv6: false, custom: false, dnsRebindingProtection: true, httpsRequired: true, verified: true },
  ] };
  const home = connectionPath(connections, 'https://192-168-1-10.k7.frameleaf.net/');
  assert.equal(home.current, 'local');
  assert.equal(home.currentLabel, 'Home network');
  assert.deepEqual(home.entries.map(entry => [entry.label, entry.current]), [['Home network', true], ['Direct', false], ['Your domain', false], ['Relay', false]]);
  assert.equal(home.entries[1]!.detail, 'public, port 2443');
  const direct = connectionPath(connections.connections, 'https://70-51-18-204.k7.frameleaf.net:2443');
  assert.equal(direct.current, 'direct');
  assert.deepEqual(pathIndicator(direct.current).map(step => step.on), [false, true, false]);
  const relay = connectionPath(connections, 'https://r.k7.frameleaf.net');
  assert.deepEqual(pathIndicator(relay.current).map(step => step.on), [false, false, true]);
  const unknown = connectionPath(connections, 'https://elsewhere.example');
  assert.equal(unknown.current, null);
  assert.equal(unknown.currentLabel, 'Unknown');
  assert.deepEqual(pathIndicator(unknown.current).map(step => step.on), [false, false, false]);
  assert.deepEqual(connectionPath(null, 'https://x').entries, []);
  assert.deepEqual(connectionPath({ connections: [{ bogus: true }] }, null).entries, []);
});

test('cloud servers and Bonjour finds merge by instance id; unlisted finds become Nearby sign-in entries', () => {
  const now = Date.UTC(2026, 10, 3);
  const cloud: CloudServer[] = [
    { instance_id: 'home', name: 'Home library', version: '1.4.2', status: 'linked', role: 'owner', presence: 'online', last_seen_at: new Date(now - 60_000).toISOString(), connections: [{ kind: 'local', uri: 'https://a', verified: true }], remote_entitled: true },
    { instance_id: 'nas', name: 'Parents’ NAS', version: '1.4.1', status: 'linked', role: 'editor', presence: 'online', last_seen_at: null, connections: [{ kind: 'relay', uri: 'https://r', verified: true }], remote_entitled: true },
    { instance_id: 'studio', name: 'Studio Mac mini', version: '1.4.0', status: 'linked', role: 'owner', presence: 'offline', last_seen_at: new Date(now - 3 * 86_400_000).toISOString(), connections: [], remote_entitled: false },
  ];
  const discovered: DiscoveredServer[] = [
    { name: 'Home library', id: 'home', url: 'https://192.168.1.10:2283', host: '192.168.1.10', port: 2283, addresses: ['192.168.1.10'], setup: 'complete', linked: true, cloud: 'available' },
    { name: 'tower', id: 'tower', url: 'http://tower.local:2283', host: 'tower.local', port: 2283, addresses: ['192.168.1.20'], setup: 'complete', linked: false, cloud: 'available' },
    { name: 'fresh', id: 'fresh', url: 'http://fresh.local:2283', host: 'fresh.local', port: 2283, addresses: [], setup: 'needed', linked: false, cloud: 'unavailable' },
  ];
  const merged = mergeServers(cloud, discovered, now);
  assert.deepEqual(merged.map(entry => entry.key), ['cloud:home', 'cloud:nas', 'cloud:studio', 'nearby:tower', 'nearby:fresh']);
  assert.equal(merged[0]!.nearby?.id, 'home');
  assert.equal(merged[0]!.detail, 'Owner · Frameleaf 1.4.2 · on your home network');
  assert.equal(merged[1]!.detail, 'Member · Frameleaf 1.4.1 · away from home, via relay');
  assert.equal(merged[2]!.online, false);
  assert.equal(merged[2]!.pill.label, 'Offline');
  assert.equal(merged[2]!.detail, 'Owner · Frameleaf 1.4.0 · last seen 3 days ago');
  assert.equal(merged[3]!.action, 'sign-in');
  assert.equal(merged[3]!.pill.label, 'Nearby');
  assert.equal(merged[3]!.detail, 'Found on this network · not linked to your account yet');
  assert.equal(merged[4]!.action, 'setup');
  assert.deepEqual(mergeServers(null, null), []);
  assert.equal(mergeServers([], discovered).length, 3);
  assert.equal(mergeServers([{ instance_id: 'x', name: 'x' }], [{ id: '', name: 'blank', url: '', host: '', port: 0, addresses: [], setup: 'complete', linked: false, cloud: 'unavailable' }]).length, 1);
});

test('platform classes and worker pills are derived from strings only', () => {
  assert.equal(platformClass('Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605'), 'platform-mac');
  assert.equal(platformClass('Mozilla/5.0 (Windows NT 10.0; Win64; x64)'), 'platform-windows');
  assert.equal(platformClass('Mozilla/5.0 (X11; Linux x86_64)'), 'platform-linux');
  assert.equal(platformClass(''), 'platform-linux');
  assert.deepEqual(workloadPill('ready'), { label: 'Ready', tone: 'ok', detail: 'Ready to help' });
  assert.equal(workloadPill('disabled').label, 'Off');
  assert.equal(workloadPill('mystery').label, 'mystery');
  assert.equal(workerTone('working'), 'ok');
  assert.equal(workerTone('paused'), 'off');
  assert.equal(workerTone('qualifying'), 'wait');
});
