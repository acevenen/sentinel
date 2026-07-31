import SwiftUI
import AppKit

/// Native monospace editor with a line-number gutter drawn by an NSRulerView, so
/// numbers are always pinned to their real glyph line fragments (no drift).
struct CodeEditor: NSViewRepresentable {
    @Binding var text: String
    var minHeight: CGFloat

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.borderType = .noBorder
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = false
        scroll.drawsBackground = false
        scroll.verticalScrollElasticity = .allowed

        let textView = NSTextView()
        textView.isRichText = false
        textView.isEditable = true
        textView.allowsUndo = true
        textView.font = NSFont.monospacedSystemFont(ofSize: 12.5, weight: .regular)
        textView.textColor = NSColor(Tok.label)
        textView.backgroundColor = NSColor(Tok.fieldBg)
        textView.drawsBackground = true
        textView.textContainerInset = NSSize(width: 8, height: 12)
        textView.isAutomaticQuoteSubstitutionEnabled = false
        textView.isAutomaticDashSubstitutionEnabled = false
        textView.isAutomaticSpellingCorrectionEnabled = false
        textView.isAutomaticTextReplacementEnabled = false
        textView.isAutomaticDataDetectionEnabled = false
        textView.smartInsertDeleteEnabled = false
        textView.delegate = context.coordinator
        textView.string = text
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.textContainer?.widthTracksTextView = true
        textView.autoresizingMask = [.width]

        scroll.documentView = textView

        let ruler = LineNumberRuler(scrollView: scroll, textView: textView)
        scroll.verticalRulerView = ruler
        scroll.hasVerticalRuler = true
        scroll.rulersVisible = true

        context.coordinator.textView = textView
        return scroll
    }

    func updateNSView(_ nsView: NSScrollView, context: Context) {
        guard let tv = nsView.documentView as? NSTextView else { return }
        if tv.string != text {
            let sel = tv.selectedRange()
            tv.string = text
            tv.setSelectedRange(NSRange(location: min(sel.location, text.utf16.count), length: 0))
            nsView.verticalRulerView?.needsDisplay = true
        }
    }

    final class Coordinator: NSObject, NSTextViewDelegate {
        let parent: CodeEditor
        weak var textView: NSTextView?
        init(_ parent: CodeEditor) { self.parent = parent }
        func textDidChange(_ notification: Notification) {
            guard let tv = notification.object as? NSTextView else { return }
            parent.text = tv.string
            tv.enclosingScrollView?.verticalRulerView?.needsDisplay = true
        }
    }
}

/// Line-number ruler: fills the gutter tint, draws a hairline divider, and
/// right-aligns numbers at each line fragment's y-position.
final class LineNumberRuler: NSRulerView {
    weak var textView: NSTextView?

    init(scrollView: NSScrollView, textView: NSTextView) {
        self.textView = textView
        super.init(scrollView: scrollView, orientation: .verticalRuler)
        self.clientView = textView
        self.ruleThickness = 38
    }
    required init(coder: NSCoder) { fatalError() }

    override func drawHashMarksAndLabels(in rect: NSRect) {
        guard let textView = self.clientView as? NSTextView,
              let layoutManager = textView.layoutManager,
              let container = textView.textContainer else { return }

        // Gutter background + right hairline divider.
        NSColor(Color.rgba(120, 120, 128, 0.06)).setFill()
        bounds.fill()
        NSColor(Tok.separator).setFill()
        NSRect(x: bounds.maxX - 0.5, y: bounds.minY, width: 0.5, height: bounds.height).fill()

        let relativePoint = self.convert(NSZeroPoint, from: textView)
        let attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedSystemFont(ofSize: 12.5, weight: .regular),
            .foregroundColor: NSColor(Tok.tertiary)
        ]
        let draw = { (str: String, y: CGFloat) in
            let s = NSAttributedString(string: str, attributes: attrs)
            let x = self.ruleThickness - 6 - s.size().width
            s.draw(at: NSPoint(x: x, y: relativePoint.y + y))
        }

        let nsString = textView.string as NSString
        let visibleGlyphRange = layoutManager.glyphRange(forBoundingRect: textView.visibleRect, in: container)
        let firstCharIndex = layoutManager.characterIndexForGlyph(at: visibleGlyphRange.location)

        var lineNumber = 1
        if firstCharIndex > 0 {
            nsString.enumerateSubstrings(in: NSRange(location: 0, length: firstCharIndex),
                                         options: [.byLines, .substringNotRequired]) { _, _, _, _ in lineNumber += 1 }
        }

        var glyphIndex = visibleGlyphRange.location
        while glyphIndex < NSMaxRange(visibleGlyphRange) {
            let charRange = nsString.lineRange(for: NSRange(location: layoutManager.characterIndexForGlyph(at: glyphIndex), length: 0))
            let lineGlyphRange = layoutManager.glyphRange(forCharacterRange: charRange, actualCharacterRange: nil)

            var idx = lineGlyphRange.location
            var wrapped = 0
            while idx < NSMaxRange(lineGlyphRange) {
                var eff = NSRange(location: 0, length: 0)
                let lineRect = layoutManager.lineFragmentRect(forGlyphAt: idx, effectiveRange: &eff, withoutAdditionalLayout: true)
                if wrapped == 0 { draw("\(lineNumber)", lineRect.minY) }
                wrapped += 1
                idx = NSMaxRange(eff)
            }
            glyphIndex = NSMaxRange(lineGlyphRange)
            lineNumber += 1
        }
        // Trailing empty line (string ends with newline, or is empty).
        if layoutManager.extraLineFragmentTextContainer != nil {
            draw("\(lineNumber)", layoutManager.extraLineFragmentRect.minY)
        }
    }
}
