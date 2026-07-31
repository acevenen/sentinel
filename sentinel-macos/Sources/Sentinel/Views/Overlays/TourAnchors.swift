import SwiftUI

/// Collects the on-screen frames of guided-tour targets via anchor preferences,
/// so the spotlight overlay can measure them without hard-coded coordinates.
struct TourAnchorKey: PreferenceKey {
    static let defaultValue: [TourTarget: Anchor<CGRect>] = [:]
    static func reduce(value: inout [TourTarget: Anchor<CGRect>], nextValue: () -> [TourTarget: Anchor<CGRect>]) {
        value.merge(nextValue()) { $1 }
    }
}

extension View {
    func tourAnchor(_ target: TourTarget) -> some View {
        anchorPreference(key: TourAnchorKey.self, value: .bounds) { [target: $0] }
    }

    @ViewBuilder
    func tourAnchorIf(_ condition: Bool, _ target: TourTarget) -> some View {
        if condition { tourAnchor(target) } else { self }
    }
}
