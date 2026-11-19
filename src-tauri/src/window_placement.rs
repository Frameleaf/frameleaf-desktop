use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, sync::Mutex};
use tauri::{AppHandle, Manager, Monitor, PhysicalPosition, PhysicalSize, WebviewWindow};

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Placement {
    x: i32,
    y: i32,
    width: f64,
    height: f64,
}

#[derive(Default)]
pub(crate) struct WindowPlacement(Mutex<Option<Placement>>);

fn path(app: &AppHandle) -> Option<PathBuf> {
    Some(
        app.path()
            .app_local_data_dir()
            .ok()?
            .join("window-placement-v1.json"),
    )
}

fn target(
    saved: Placement,
    area: (i32, i32, u32, u32),
    scale: f64,
    frame: (u32, u32),
    same_display: bool,
) -> Option<(PhysicalPosition<i32>, PhysicalSize<u32>)> {
    let (left, top, width, height) = area;
    let (usable_width, usable_height) = (width.checked_sub(frame.0)?, height.checked_sub(frame.1)?);
    if !(saved.width >= 320. && saved.height >= 240. && scale > 0.)
        || usable_width == 0
        || usable_height == 0
    {
        return None;
    }
    let size = PhysicalSize::new(
        (saved.width * scale).round().min(f64::from(usable_width)) as u32,
        (saved.height * scale).round().min(f64::from(usable_height)) as u32,
    );
    let position = |value, start, space, extent| {
        let room = i64::from(space) - i64::from(extent);
        let start = i64::from(start);
        let value = if same_display {
            i64::from(value).clamp(start, start + room)
        } else {
            start + room / 2
        };
        i32::try_from(value).ok()
    };
    Some((
        PhysicalPosition::new(
            position(saved.x, left, usable_width, size.width)?,
            position(saved.y, top, usable_height, size.height)?,
        ),
        size,
    ))
}

fn position_scale(scale: f64) -> f64 {
    // Cocoa and GTK express global coordinates in points. Windows uses desktop pixels.
    if cfg!(target_os = "windows") {
        1.
    } else {
        scale
    }
}

fn work_area(monitor: &Monitor) -> (i32, i32, u32, u32) {
    let area = monitor.work_area();
    let scale = position_scale(monitor.scale_factor());
    let point = area.position.to_logical::<i32>(scale);
    let size = area.size.to_logical::<u32>(scale);
    (point.x, point.y, size.width, size.height)
}

impl WindowPlacement {
    pub(crate) fn restore(&self, window: &WebviewWindow) {
        let Some(saved) = path(window.app_handle())
            .and_then(|file| fs::read(file).ok())
            .and_then(|bytes| serde_json::from_slice::<Placement>(&bytes).ok())
        else {
            return;
        };
        let monitors = window.available_monitors().unwrap_or_default();
        let previous = monitors.iter().find(|monitor| {
            let (left, top, width, height) = work_area(monitor);
            let (x, y) = (
                i64::from(saved.x) - i64::from(left),
                i64::from(saved.y) - i64::from(top),
            );
            (0..i64::from(width)).contains(&x) && (0..i64::from(height)).contains(&y)
        });
        let primary = window.primary_monitor().ok().flatten();
        let Some(monitor) = previous.or(primary.as_ref()).or(monitors.first()) else {
            return;
        };
        let scale = monitor.scale_factor() / position_scale(monitor.scale_factor());
        let window_scale = window.scale_factor().unwrap_or(1.);
        let frame = window
            .outer_size()
            .ok()
            .zip(window.inner_size().ok())
            .map_or((0, 0), |(outer, inner)| {
                let to_target =
                    |extent: u32| (f64::from(extent) / window_scale * scale).ceil() as u32;
                (
                    to_target(outer.width.saturating_sub(inner.width)),
                    to_target(outer.height.saturating_sub(inner.height)),
                )
            });
        if let Some((position, size)) =
            target(saved, work_area(monitor), scale, frame, previous.is_some())
        {
            if cfg!(target_os = "windows") {
                let _ = window.set_position(position);
                let _ = window.set_size(size);
            } else {
                let _ = window.set_position(position.to_logical::<i32>(1.));
                let _ = window.set_size(size.to_logical::<u32>(1.));
            }
        }
    }

    pub(crate) fn remember(&self, window: &WebviewWindow) {
        if window.is_minimized().unwrap_or(true)
            || window.is_maximized().unwrap_or(true)
            || window.is_fullscreen().unwrap_or(true)
        {
            return;
        }
        let (Ok(position), Ok(size), Ok(scale)) = (
            window.outer_position(),
            window.inner_size(),
            window.scale_factor(),
        ) else {
            return;
        };
        let position = position.to_logical::<i32>(position_scale(scale));
        let size = size.to_logical::<f64>(scale);
        if size.width >= 320. && size.height >= 240. {
            if let Ok(mut saved) = self.0.lock() {
                *saved = Some(Placement {
                    x: position.x,
                    y: position.y,
                    width: size.width,
                    height: size.height,
                });
            }
        }
    }

    pub(crate) fn save(&self, app: &AppHandle) {
        let Some((saved, file)) = self.0.lock().ok().and_then(|saved| (*saved).zip(path(app)))
        else {
            return;
        };
        let Some(directory) = file.parent() else {
            return;
        };
        if let Ok(bytes) = serde_json::to_vec(&saved) {
            if fs::read(&file).ok().as_deref() != Some(bytes.as_slice())
                && fs::create_dir_all(directory).is_ok()
            {
                let _ = fs::write(file, bytes);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_window_to_work_area_at_current_scale() {
        let saved = Placement {
            x: -800,
            y: 800,
            width: 1100.,
            height: 740.,
        };
        let area = (-1920, 40, 1920, 1000);
        let (point, size) = target(saved, area, 2., (0, 40), true).unwrap();
        assert_eq!(point, PhysicalPosition::new(-1920, 40));
        assert_eq!(size, PhysicalSize::new(1920, 960));
    }

    #[test]
    fn centers_window_when_previous_display_is_gone() {
        let saved = Placement {
            x: 4000,
            y: -2000,
            width: 1040.,
            height: 760.,
        };
        let (point, size) = target(saved, (0, 25, 1600, 950), 1., (16, 32), false).unwrap();
        assert_eq!(point, PhysicalPosition::new(272, 104));
        assert_eq!(size, PhysicalSize::new(1040, 760));
    }

    #[test]
    fn rejects_invalid_placement_or_unusable_area() {
        let saved = Placement {
            x: 0,
            y: 0,
            width: 0.,
            height: 760.,
        };
        assert!(target(saved, (0, 0, 1920, 1080), 1., (0, 0), false).is_none());
        let valid = Placement {
            width: 1040.,
            ..saved
        };
        assert!(target(valid, (0, 0, 0, 1080), 1., (0, 0), false).is_none());
    }
}
