// Launch only the installed copy on a disposable account, without UI scripting or reading credentials.
import AppKit
import CoreGraphics
import Foundation

guard ProcessInfo.processInfo.environment["RUNNER_ENVIRONMENT"] == "github-hosted",
      CommandLine.arguments.count == 2 else { fatalError("A disposable hosted Mac is required") }
let url = URL(fileURLWithPath: CommandLine.arguments[1]).resolvingSymlinksInPath()
let deadline = Date().addingTimeInterval(60)
var launched: NSRunningApplication?
var ready = false
while Date() < deadline {
    launched = NSRunningApplication.runningApplications(withBundleIdentifier: "app.frameleaf.desktop")
        .first { $0.bundleURL?.resolvingSymlinksInPath().path == url.path }
    let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]]
    if let app = launched, app.isFinishedLaunching, (windows ?? []).contains(where: { window in
        (window[kCGWindowOwnerPID as String] as? Int32) == app.processIdentifier &&
        (window[kCGWindowLayer as String] as? Int) == 0
    }) {
        ready = true
        break
    }
    RunLoop.current.run(until: Date().addingTimeInterval(0.5))
}
if let app = launched { _ = app.terminate() }
guard ready else { fatalError("Installed Frameleaf GUI did not open a window") }
print("Installed Developer ID application launched and displayed its window.")
