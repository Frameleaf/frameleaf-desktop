//! FL-1760: the FFmpeg options a server may ask a desktop to run. They are untrusted, so each flag
//! and the shape of its value is listed here, from what the server's `utils/media.ts` emits for a
//! software encode. Anything else refuses the whole command. Paths are only ever chosen here.
use std::{collections::BTreeSet, ffi::OsString, path::Path};

const MAX_OPTIONS: usize = 96;
/// Containers the library accepts as video. Leaving out `hls`, `concat`, `image2` and the like
/// matters: those read other files named inside the input, whatever the protocol list says.
const INPUT_FORMATS: &str = "mov,matroska,webm,avi,asf,flv,mpegts,mpeg,mpegvideo,m4v,h264,hevc,vc1,ivf,mjpeg,dv,gxf,mxf,nut,ogg,rm,wtv,yuv4mpegpipe";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Pass {
    Only,
    First,
    Second,
}

fn number(value: &str, low: u32, high: u32) -> bool {
    !value.is_empty()
        && value.len() <= 6
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
        && value
            .parse::<u32>()
            .is_ok_and(|n| (low..=high).contains(&n))
}
/// `2000k`, or the `690.5k` that half of an odd target comes to.
fn bitrate(value: &str) -> bool {
    let digits = value.strip_suffix(['k', 'K', 'm', 'M']).unwrap_or(value);
    let (whole, fraction) = digits.split_once('.').unwrap_or((digits, "0"));
    number(whole, 0, 9_999_999)
        && !fraction.is_empty()
        && fraction.len() <= 3
        && fraction.bytes().all(|byte| byte.is_ascii_digit())
}
fn stream(value: &str) -> bool {
    value
        .strip_prefix("0:")
        .is_some_and(|index| number(index, 0, 1024))
}
fn scale(value: &str) -> bool {
    let Some((width, height)) = value.split_once(':') else {
        return false;
    };
    let side = |text: &str| number(text, 2, 16384);
    (width == "-2" && side(height)) || (height == "-2" && side(width))
}
fn tone_map(value: &str) -> bool {
    ["hable", "mobius", "reinhard"].iter().any(|curve| {
        value
            == format!(
                "tonemap={curve}:desat=0:p=bt709:t=bt709:m=bt709:r=pc:peak=100:format=yuv420p"
            )
    })
}
/// Only `scale`, `format` and `tonemapx`, each once. None of them can name a file.
fn filters(value: &str) -> bool {
    let mut seen = BTreeSet::new();
    value.split(',').all(|filter| {
        let Some((name, options)) = filter.split_once('=') else {
            return false;
        };
        seen.insert(name)
            && match name {
                "scale" => scale(options),
                "format" => options == "yuv420p",
                "tonemapx" => tone_map(options),
                _ => false,
            }
    })
}
fn params(value: &str, allowed: impl Fn(&str, &str) -> bool) -> bool {
    let mut seen = BTreeSet::new();
    value.split(':').all(|pair| {
        pair.split_once('=')
            .is_some_and(|(key, item)| seen.insert(key) && allowed(key, item))
    })
}
fn value_allowed(flag: &str, value: &str) -> Option<bool> {
    Some(match flag {
        "-c:v" => ["libx264", "libx265", "vp9", "libsvtav1", "copy"].contains(&value),
        "-c:a" => ["aac", "libopus", "mp3", "pcm_s16le", "copy"].contains(&value),
        "-map" => stream(value),
        "-map_metadata" => value == "-1",
        "-ac" => number(value, 1, 8),
        "-bf" => number(value, 0, 16),
        "-refs" => number(value, 1, 16),
        "-g" | "-keyint_min" => number(value, 1, 100_000),
        "-tag:v" => value == "hvc1",
        "-preset" => {
            [
                "veryslow",
                "slower",
                "slow",
                "medium",
                "fast",
                "faster",
                "veryfast",
                "superfast",
                "ultrafast",
            ]
            .contains(&value)
                || number(value, 4, 12)
        }
        "-cpu-used" => number(value, 0, 5),
        "-crf" | "-q:v" => number(value, 0, 63),
        "-b:v" | "-minrate" | "-maxrate" | "-bufsize" => bitrate(value),
        "-threads" => number(value, 1, 1024),
        "-row-mt" => value == "1",
        "-sc_threshold:v" => value == "0",
        "-movflags" => value == "faststart",
        "-fps_mode" => value == "passthrough",
        "-v" => value == "verbose",
        "-vf" => filters(value),
        "-x264-params" => value == "frame-threads=1:pools=none",
        "-x265-params" => params(value, |key, item| {
            matches!(
                (key, item),
                ("no-scenecut", "1")
                    | ("no-open-gop", "1")
                    | ("frame-threads", "1")
                    | ("pools", "none")
            )
        }),
        "-svtav1-params" => params(value, |key, item| match key {
            "hierarchical-levels" => item == "3",
            "lookahead" | "enable-tf" => item == "0",
            "lp" => number(item, 1, 1024),
            "mbr" => bitrate(item),
            _ => false,
        }),
        _ => return None,
    })
}

/// The server's options, checked. A software command has no input options at all.
pub(crate) fn validate(input: &[String], output: &[String]) -> Result<Vec<String>, String> {
    let refused = || "transcode_options_refused".to_string();
    if !input.is_empty() || output.len() > MAX_OPTIONS || !output.len().is_multiple_of(2) {
        return Err(refused());
    }
    let mut seen = BTreeSet::new();
    let mut maps = 0;
    for pair in output.as_chunks::<2>().0 {
        let (flag, value) = (pair[0].as_str(), pair[1].as_str());
        if value_allowed(flag, value) != Some(true) {
            return Err(refused());
        }
        if flag == "-map" {
            maps += 1;
        } else if !seen.insert(flag) {
            return Err(refused());
        }
    }
    if !(1..=2).contains(&maps) || !seen.contains("-c:v") || !seen.contains("-c:a") {
        return Err(refused());
    }
    Ok(output.to_vec())
}

/// The whole command line. No shell is involved, and only this function names a path.
pub(crate) fn ffmpeg_args(
    input: &Path,
    output: &Path,
    pass_log: &Path,
    options: &[String],
    pass: Pass,
) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        "-nostdin",
        "-hide_banner",
        "-nostats",
        "-progress",
        "pipe:1",
        "-protocol_whitelist",
        "file,pipe",
        "-format_whitelist",
        INPUT_FORMATS,
        "-i",
    ]
    .map(OsString::from)
    .into();
    args.push(input.into());
    args.extend(options.iter().map(OsString::from));
    let number = match pass {
        Pass::Only => None,
        Pass::First => Some("1"),
        Pass::Second => Some("2"),
    };
    if let Some(number) = number {
        args.extend(["-pass", number, "-passlogfile"].map(OsString::from));
        args.push(pass_log.into());
    }
    if pass == Pass::First {
        args.extend(["-f", "null", "-"].map(OsString::from));
    } else {
        args.extend(["-f", "mp4"].map(OsString::from));
        args.push(output.as_os_str().to_owned());
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;
    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_string()).collect()
    }
    fn base() -> Vec<&'static str> {
        vec![
            "-c:v",
            "libx264",
            "-c:a",
            "aac",
            "-map",
            "0:0",
            "-map_metadata",
            "-1",
            "-map",
            "0:1",
            "-ac",
            "2",
            "-preset",
            "ultrafast",
            "-crf",
            "23",
            "-movflags",
            "faststart",
            "-fps_mode",
            "passthrough",
            "-v",
            "verbose",
        ]
    }
    fn accepted(extra: &[&str]) -> bool {
        let mut options = base();
        options.extend(extra);
        validate(&[], &list(&options)).is_ok()
    }
    fn swap(flag: &str, value: &'static str) -> Vec<String> {
        let mut options = base();
        let at = options.iter().position(|item| *item == flag).unwrap();
        options[at + 1] = value;
        list(&options)
    }

    #[test]
    fn accepts_what_the_server_emits_for_each_software_encoder() {
        assert!(accepted(&[]));
        assert!(accepted(&["-vf", "scale=-2:720,format=yuv420p"]));
        assert!(accepted(&["-vf", "scale=720:-2"]));
        assert!(accepted(&[
            "-vf",
            "scale=-2:1080,tonemapx=tonemap=hable:desat=0:p=bt709:t=bt709:m=bt709:r=pc:peak=100:format=yuv420p"
        ]));
        assert!(accepted(&[
            "-bf",
            "3",
            "-refs",
            "3",
            "-g",
            "250",
            "-keyint_min",
            "250"
        ]));
        assert!(accepted(&[
            "-threads",
            "1",
            "-x264-params",
            "frame-threads=1:pools=none"
        ]));
        assert!(accepted(&["-sc_threshold:v", "0"]));
        assert!(accepted(&["-maxrate", "2000k", "-bufsize", "4000k"]));
        assert!(accepted(&[
            "-b:v", "1380k", "-minrate", "690.5k", "-maxrate", "2000k"
        ]));
        assert!(accepted(&[
            "-tag:v",
            "hvc1",
            "-x265-params",
            "no-scenecut=1:no-open-gop=1:frame-threads=1:pools=none"
        ]));
        assert!(validate(&[], &swap("-c:v", "libx265")).is_ok());
        assert!(validate(&[], &swap("-c:v", "copy")).is_ok());
        assert!(validate(&[], &swap("-c:a", "copy")).is_ok());
        assert!(validate(&[], &swap("-preset", "12")).is_ok());
        let vp9 = list(&[
            "-c:v",
            "vp9",
            "-c:a",
            "libopus",
            "-map",
            "0:0",
            "-map_metadata",
            "-1",
            "-cpu-used",
            "5",
            "-crf",
            "23",
            "-b:v",
            "0k",
            "-row-mt",
            "1",
            "-threads",
            "4",
            "-movflags",
            "faststart",
            "-fps_mode",
            "passthrough",
            "-v",
            "verbose",
        ]);
        assert!(validate(&[], &vp9).is_ok());
        let av1 = list(&[
            "-c:v",
            "libsvtav1",
            "-c:a",
            "aac",
            "-map",
            "0:0",
            "-map_metadata",
            "-1",
            "-preset",
            "12",
            "-crf",
            "30",
            "-svtav1-params",
            "hierarchical-levels=3:lookahead=0:enable-tf=0:lp=2:mbr=2000k",
            "-movflags",
            "faststart",
            "-fps_mode",
            "passthrough",
            "-v",
            "verbose",
        ]);
        assert!(validate(&[], &av1).is_ok());
    }

    #[test]
    fn refuses_flags_that_reach_outside_the_job() {
        for flag in [
            "-i",
            "-filter_complex",
            "-lavfi",
            "-f",
            "-filter:v",
            "-af",
            "-attach",
            "-dump_attachment",
            "-passlogfile",
            "-pass",
            "-vstats_file",
            "-progress",
            "-report",
            "-protocol_whitelist",
            "-safe",
            "-y",
            "-init_hw_device",
            "-hwaccel",
            "-bsf:v",
            "/tmp/out.mp4",
        ] {
            assert!(!accepted(&[flag, "1"]), "{flag}");
        }
        assert!(validate(&list(&["-i", "/etc/passwd"]), &list(&base())).is_err());
        assert!(validate(&list(&["-threads", "1"]), &list(&base())).is_err());
    }

    #[test]
    fn refuses_paths_urls_and_protocols_as_values() {
        for value in [
            "/etc/passwd",
            "../secret",
            "C:\\Windows\\win.ini",
            "file:/etc/passwd",
            "http://example.test/a",
            "https://example.test/a",
            "concat:a|b",
            "pipe:1",
            "data:text/plain,x",
            "subfile,,start,0,end,0,,:/etc/passwd",
        ] {
            for flag in [
                "-c:v",
                "-c:a",
                "-map",
                "-preset",
                "-b:v",
                "-vf",
                "-movflags",
                "-x264-params",
            ] {
                let mut options = base();
                options.extend([flag]);
                options.push(value);
                assert!(validate(&[], &list(&options)).is_err(), "{flag} {value}");
            }
        }
    }

    #[test]
    fn refuses_filters_that_read_files_and_anything_unlisted() {
        for chain in [
            "movie=/etc/passwd",
            "amovie=/etc/passwd",
            "lut3d=file=/tmp/a.cube",
            "lut3d=/tmp/a.cube:interp=tetrahedral",
            "subtitles=/etc/passwd",
            "ass=/etc/passwd",
            "drawtext=textfile=/etc/passwd",
            "curves=psfile=/etc/passwd",
            "sendcmd=f=/etc/passwd",
            "libplacebo=custom_shader_path=/tmp/a",
            "v360=input=e",
            "scale=-2:720,movie=/etc/passwd",
            "scale=-2:720;movie=/etc/passwd",
            "scale=-2:720[a];[a]movie=/etc/passwd",
            "scale=-2:720:flags=lanczos",
            "scale=1920:1080",
            "scale=-2:720,scale=-2:480",
            "format=yuv420p:x",
            "tonemapx=tonemap=hable:file=/etc/passwd",
            "",
        ] {
            assert!(!accepted(&["-vf", chain]), "{chain}");
        }
    }

    #[test]
    fn refuses_encoder_params_that_write_or_read_files() {
        assert!(!accepted(&["-x264-params", "stats=/tmp/a"]));
        assert!(!accepted(&["-x264-params", "dump-yuv=/tmp/a"]));
        assert!(!accepted(&["-x265-params", "csv=/tmp/a"]));
        assert!(!accepted(&["-x265-params", "pools=none:pools=none"]));
        assert!(!accepted(&["-svtav1-params", "stat-file=/tmp/a"]));
    }

    #[test]
    fn refuses_malformed_commands() {
        assert!(validate(&[], &list(&["-c:v"])).is_err());
        assert!(validate(&[], &[]).is_err());
        assert!(!accepted(&["-crf", "20"]), "repeated flag");
        assert!(!accepted(&["-map", "0:2"]), "third map");
        assert!(validate(&[], &swap("-map", "1:0")).is_err());
        assert!(validate(&[], &swap("-c:v", "h264_nvenc")).is_err());
        assert!(validate(&[], &swap("-crf", "-1")).is_err());
        assert!(validate(&[], &swap("-crf", "+1")).is_err());
        assert!(validate(&[], &swap("-preset", "placebo")).is_err());
        let long = vec!["-v".to_string(); MAX_OPTIONS + 2];
        assert!(validate(&[], &long).is_err());
    }

    #[test]
    fn the_command_line_is_chosen_here_and_two_passes_write_only_the_second() {
        let options = list(&base());
        let (input, output, log) = (
            Path::new("/job/input"),
            Path::new("/job/output.mp4"),
            Path::new("/job/pass"),
        );
        let text = |pass| -> Vec<String> {
            ffmpeg_args(input, output, log, &options, pass)
                .into_iter()
                .map(|arg| arg.into_string().unwrap())
                .collect()
        };
        let only = text(Pass::Only);
        assert_eq!(only[0], "-nostdin");
        assert!(only.windows(2).any(|pair| pair == ["-progress", "pipe:1"]));
        let protocols = only
            .iter()
            .position(|a| a == "-protocol_whitelist")
            .unwrap();
        let formats = only.iter().position(|a| a == "-format_whitelist").unwrap();
        let source = only.iter().position(|a| a == "-i").unwrap();
        assert_eq!(only[protocols + 1], "file,pipe");
        assert!(protocols < source && formats < source);
        for format in ["hls", "concat", "image2", "tty", "lavfi"] {
            assert!(!only[formats + 1].split(',').any(|name| name == format));
        }
        assert_eq!(only[source + 1], "/job/input");
        assert_eq!(only.last().unwrap(), "/job/output.mp4");
        assert!(!only.iter().any(|a| a == "-pass"));
        let first = text(Pass::First);
        assert!(first.ends_with(&list(&["-f", "null", "-"])));
        assert!(!first.iter().any(|a| a == "/job/output.mp4"));
        let second = text(Pass::Second);
        assert!(second.windows(2).any(|pair| pair == ["-pass", "2"]));
        assert!(second
            .windows(2)
            .any(|pair| pair == ["-passlogfile", "/job/pass"]));
        assert_eq!(second.last().unwrap(), "/job/output.mp4");
    }
}
