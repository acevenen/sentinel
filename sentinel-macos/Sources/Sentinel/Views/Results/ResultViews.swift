import SwiftUI

struct ResultSection: View {
    @Environment(AppModel.self) private var model
    let result: ToolResult

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            // "Result" divider
            HStack(spacing: 8) {
                Sym("bar-chart-3", size: 15).foregroundStyle(Tok.secondary)
                Text("Result").font(.system(size: 13, weight: .semibold)).foregroundStyle(Tok.secondary)
                Rectangle().fill(Tok.separator).frame(height: 0.5)
            }
            .padding(.bottom, 0)

            if let s = result.score { ScoreBannerView(score: s) }
            if let h = result.headline { HeadlineStrip(headline: h) }
            if let t = result.table { ResultTableView(table: t) }
            if let f = result.findings { FindingsList(findings: f) }
            if let a = result.argv { ArgvBlockView(block: a) }
            if let r = result.report { ReportBlock(text: r) }
        }
        .padding(.top, 26)
    }
}

// MARK: - Score banner

struct ScoreBannerView: View {
    let score: ScoreBanner
    var body: some View {
        HStack(spacing: 22) {
            VStack(spacing: 2) {
                Text("\(score.score)")
                    .font(.system(size: 48, weight: .bold)).tracking(-1.4)
                    .foregroundStyle(score.color)
                Text("/ 100").font(.system(size: 12, weight: .semibold)).foregroundStyle(Tok.secondary)
            }
            VStack(alignment: .leading, spacing: 9) {
                Text(score.rec)
                    .font(.system(size: 13, weight: .bold)).tracking(0.2)
                    .foregroundStyle(score.recKind.fg)
                    .padding(.horizontal, 13).padding(.vertical, 5)
                    .background(RoundedRectangle(cornerRadius: Tok.rButtonSm).fill(score.recKind.bg))
                Text(score.note).font(.system(size: 13)).foregroundStyle(Tok.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 24).padding(.vertical, 22)
        .background(
            RoundedRectangle(cornerRadius: Tok.rCardLg, style: .continuous)
                .fill(LinearGradient(colors: [Color.white, Color(hex: "#F7F9FF")], startPoint: .topLeading, endPoint: .bottomTrailing))
                .overlay(RoundedRectangle(cornerRadius: Tok.rCardLg, style: .continuous).strokeBorder(Tok.separator, lineWidth: 0.5))
        )
        .cardShadow()
    }
}

// MARK: - Headline strip

struct HeadlineStrip: View {
    let headline: Headline
    var body: some View {
        HStack(spacing: 12) {
            Sym(headline.icon, size: 20).foregroundStyle(headline.kind.fg)
            VStack(alignment: .leading, spacing: 2) {
                Text(headline.title).font(.system(size: 14.5, weight: .semibold)).foregroundStyle(headline.kind.fg)
                Text(headline.sub).font(.system(size: 12.5)).foregroundStyle(headline.kind.fg.opacity(0.85))
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 17).padding(.vertical, 15)
        .background(
            RoundedRectangle(cornerRadius: Tok.rField, style: .continuous)
                .fill(headline.kind.stripBg)
                .overlay(RoundedRectangle(cornerRadius: Tok.rField, style: .continuous).strokeBorder(headline.kind.stripBorder, lineWidth: 0.5))
        )
    }
}

// MARK: - Table

struct ResultTableView: View {
    let table: ResultTable

    private func isFlexible(_ index: Int, _ label: String) -> Bool {
        index == table.cols.count - 1 || label == "URL"
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack(spacing: 0) {
                ForEach(Array(table.cols.enumerated()), id: \.offset) { i, col in
                    Text(col.uppercased())
                        .font(.system(size: 11, weight: .bold)).tracking(0.3)
                        .foregroundStyle(Tok.tertiary)
                        .columnFrame(width: isFlexible(i, col) ? nil : ResultTable.width(for: col))
                }
            }
            .padding(.horizontal, 14).padding(.vertical, 9)

            ForEach(table.rows) { r in
                Rectangle().fill(Tok.separator).frame(height: 0.5)
                HStack(spacing: 0) {
                    ForEach(Array(r.cells.enumerated()), id: \.offset) { i, cell in
                        cellView(cell)
                            .columnFrame(width: isFlexible(i, i < table.cols.count ? table.cols[i] : "") ? nil : ResultTable.width(for: i < table.cols.count ? table.cols[i] : ""))
                    }
                }
                .padding(.horizontal, 14).padding(.vertical, 10)
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 13, style: .continuous).fill(Color.white)
                .overlay(RoundedRectangle(cornerRadius: 13, style: .continuous).strokeBorder(Tok.separator, lineWidth: 0.5))
        )
        .clipShape(RoundedRectangle(cornerRadius: 13, style: .continuous))
        .cardShadow()
    }

    @ViewBuilder
    private func cellView(_ cell: ResultCell) -> some View {
        if let kind = cell.pill {
            HStack { Pill(text: cell.text, kind: kind); Spacer(minLength: 0) }
        } else {
            Text(cell.text)
                .font(.system(size: 12.5)).foregroundStyle(Tok.label)
                .lineLimit(1).truncationMode(.tail)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.trailing, 8)
        }
    }
}

private extension View {
    /// Fixed-width column, or flexible (fills remaining) when width is nil.
    @ViewBuilder func columnFrame(width: CGFloat?) -> some View {
        if let width { self.frame(width: width, alignment: .leading) }
        else { self.frame(maxWidth: .infinity, alignment: .leading) }
    }
}

// MARK: - Findings

struct FindingsList: View {
    let findings: [Finding]
    var body: some View {
        VStack(spacing: 10) {
            ForEach(findings) { FindingCard(finding: $0) }
        }
    }
}

struct FindingCard: View {
    @Environment(\.accentChoice) private var accent
    let finding: Finding
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 9) {
                SeverityPill(sev: finding.sev)
                Text(finding.title).font(.system(size: 14, weight: .semibold))
                Spacer(minLength: 8)
                Text(finding.tag).font(Tok.monoFont(11.5)).foregroundStyle(Tok.tertiary)
            }
            Text(finding.loc).font(Tok.monoFont(12.5)).foregroundStyle(accent.accent2).padding(.top, 2)
            Text(finding.desc).font(.system(size: 13)).foregroundStyle(Tok.secondary).fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 17).padding(.vertical, 15)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            ZStack(alignment: .leading) {
                RoundedRectangle(cornerRadius: 13, style: .continuous).fill(Color.white)
                    .overlay(RoundedRectangle(cornerRadius: 13, style: .continuous).strokeBorder(Tok.separator, lineWidth: 0.5))
                Rectangle().fill(finding.color).frame(width: 3)
                    .clipShape(RoundedRectangle(cornerRadius: 2))
            }
        )
        .clipShape(RoundedRectangle(cornerRadius: 13, style: .continuous))
        .cardShadow()
    }
}

struct SeverityPill: View {
    let sev: String
    private var fg: Color { switch sev { case "CRITICAL": return Tok.badFg; case "HIGH": return Tok.warnFg; default: return Color(hex: "#8A6D00") } }
    private var bg: Color { switch sev { case "CRITICAL": return Tok.badBg; case "HIGH": return Tok.warnBg; default: return Color.rgba(255, 204, 0, 0.2) } }
    var body: some View {
        Text(sev).font(.system(size: 11, weight: .bold)).tracking(0.2)
            .foregroundStyle(fg)
            .padding(.horizontal, 9).padding(.vertical, 2)
            .background(RoundedRectangle(cornerRadius: Tok.rChip).fill(bg))
    }
}

// MARK: - Argv block

struct ArgvBlockView: View {
    @Environment(AppModel.self) private var model
    let block: ArgvBlock
    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Sym("terminal", size: 14).foregroundStyle(Tok.secondary)
                Text("Exact argv · nothing was sent").font(.system(size: 12, weight: .semibold)).foregroundStyle(Tok.secondary)
                Spacer()
                HoverTextButton(icon: "copy", label: "Copy") { model.setClipboard(block.argv) }
            }
            .padding(.horizontal, 14).padding(.vertical, 10)
            .background(Color.rgba(120, 120, 128, 0.08))
            .overlay(alignment: .bottom) { Rectangle().fill(Tok.separator).frame(height: 0.5) }

            HStack {
                Text(block.argv).font(Tok.monoFont(12.5)).foregroundStyle(Tok.terminalFg)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Spacer(minLength: 0)
            }
            .padding(14)
            .background(Tok.terminalBg)

            HStack(spacing: 10) {
                Sym("link-2", size: 14).foregroundStyle(Tok.green)
                Text("audit +1 · \(block.audit)").font(Tok.monoFont(12)).foregroundStyle(Tok.secondary)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 14).padding(.vertical, 11)
            .background(Color.white)
        }
        .clipShape(RoundedRectangle(cornerRadius: 13, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 13, style: .continuous).strokeBorder(Tok.separator, lineWidth: 0.5))
        .cardShadow()
    }
}

// MARK: - Report block

struct ReportBlock: View {
    @Environment(AppModel.self) private var model
    let text: String
    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack {
                Text("HackerOne-ready report").font(.system(size: 13, weight: .semibold))
                Spacer()
                SmallGlassButton(label: "Copy report", icon: "copy") { model.setClipboard(text) }
            }
            ScrollView {
                Text(text).font(Tok.monoFont(12)).foregroundStyle(Tok.label)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(14)
            }
            .frame(maxHeight: 220)
            .background(
                RoundedRectangle(cornerRadius: Tok.rField, style: .continuous).fill(Tok.fieldBg)
                    .overlay(RoundedRectangle(cornerRadius: Tok.rField, style: .continuous).strokeBorder(Tok.separator, lineWidth: 0.5))
            )
        }
    }
}
