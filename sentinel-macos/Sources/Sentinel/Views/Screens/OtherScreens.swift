import SwiftUI

// MARK: - Demo data (mirrors doctorData / engageData / auditData / steps)

enum DemoData {
    struct Step: Identifiable { let id = UUID(); let n: String; let title: String; let body: String; let icon: String }
    static let steps: [Step] = [
        Step(n: "1", title: "Capture your two test accounts",
             body: "Open DevTools → Network, browse as account A, then Save all as HAR. Repeat as account B.", icon: "radio"),
        Step(n: "2", title: "Import the captures",
             body: "Drop each HAR into Hunt → Import. Sentinel keeps read-only requests with an ID and records which objects each account owns.", icon: "import"),
        Step(n: "3", title: "Confirm scope",
             body: "Review the generated manifest. Every request is checked against in_scope / out_of_scope before it is sent.", icon: "crosshair"),
        Step(n: "4", title: "Add your session tokens",
             body: "Paste each test account\u{2019}s token into the run panel. Tokens live only in memory for the run.", icon: "key-round"),
        Step(n: "5", title: "Dry-run, then run",
             body: "Dry-run shows every request and its scope decision without sending anything. Then Run produces a report per finding.", icon: "play")
    ]

    struct DoctorItem: Identifiable { let id = UUID(); let name: String; let cap: String; let icon: String; let chip: Color; let ok: Bool; let status: String }
    static let doctor: [DoctorItem] = [
        DoctorItem(name: "nmap", cap: "ready · cap_net_raw granted", icon: "radar", chip: Tok.authorizedBlue, ok: true, status: "Ready"),
        DoctorItem(name: "tshark", cap: "ready · cap_net_admin granted", icon: "waves", chip: Tok.authorizedBlue, ok: true, status: "Ready"),
        DoctorItem(name: "skipfish", cap: "ready", icon: "flask-conical", chip: Tok.authorizedBlue, ok: true, status: "Ready"),
        DoctorItem(name: "sqlmap", cap: "ready · attestation required to run", icon: "flask-conical", chip: Tok.authorizedBlue, ok: true, status: "Ready"),
        DoctorItem(name: "hashcat", cap: "ready · offline only", icon: "key-round", chip: Tok.highRed, ok: true, status: "Ready"),
        DoctorItem(name: "aircrack-ng", cap: "ready · offline only", icon: "wifi", chip: Tok.highRed, ok: true, status: "Ready"),
        DoctorItem(name: "hping3", cap: "ready · cap_net_raw granted", icon: "radar", chip: Tok.authorizedBlue, ok: true, status: "Ready"),
        DoctorItem(name: "metasploit", cap: "not found · make dev to install", icon: "crosshair", chip: Tok.highRed, ok: false, status: "Setup"),
        DoctorItem(name: "set (toolkit)", cap: "not found · make dev to install", icon: "message-square-warning", chip: Tok.highRed, ok: false, status: "Setup"),
        DoctorItem(name: "kali-utils", cap: "partial · whatweb missing", icon: "wrench", chip: Tok.opsGrey, ok: false, status: "Setup")
    ]

    struct Engagement: Identifiable { let id = UUID(); let name: String; let ref: String; let dot: Color; let scope: String; let auth: String; let attested: Bool; let attestLabel: String; let events: Int }
    static let engagements: [Engagement] = [
        Engagement(name: "Owned local lab", ref: "local-lab", dot: Tok.green, scope: "http://127.0.0.1:3000", auth: "local-owner · attested", attested: true, attestLabel: "Attested", events: 14),
        Engagement(name: "Acme public program", ref: "acme-web", dot: Tok.authorizedBlue, scope: "*.acme.com", auth: "hackerone · h1-enrolled", attested: false, attestLabel: "Not attested", events: 6),
        Engagement(name: "Local LLM eval", ref: "local-llm", dot: Tok.aiViolet, scope: "http://127.0.0.1:4010", auth: "owner-approved", attested: true, attestLabel: "Attested", events: 9)
    ]

    struct Audit: Identifiable { let id = UUID(); let action: String; let hash: String; let time: String; let icon: String; let chip: Color }
    static let audit: [Audit] = [
        Audit(action: "engagement.create · local-lab", hash: "sha256:9f2a…c1 · genesis", time: "09:14:02", icon: "file-plus", chip: Tok.authorizedBlue),
        Audit(action: "recon.dryrun · nmap 127.0.0.1", hash: "sha256:3b7d…4a · prev 9f2a", time: "09:15:40", icon: "radar", chip: Tok.authorizedBlue),
        Audit(action: "authz.check · in-scope allow", hash: "sha256:71ee…90 · prev 3b7d", time: "09:15:41", icon: "shield-check", chip: Tok.green),
        Audit(action: "orchestrate.plan · 4 stages", hash: "sha256:c40a…2f · prev 71ee", time: "09:18:22", icon: "workflow", chip: Tok.aiViolet)
    ]
}

// MARK: - Point at a Project

struct HowToView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.accentChoice) private var accent

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Point Sentinel at a project").font(.system(size: 26, weight: .bold)).tracking(-0.5)
            Text("The fastest path from \u{201C}I found an endpoint\u{201D} to a submittable report — five steps.")
                .font(.system(size: 15)).foregroundStyle(Tok.secondary).padding(.top, 6)

            VStack(spacing: 12) {
                ForEach(DemoData.steps) { step in
                    HStack(spacing: 16) {
                        Text(step.n)
                            .font(.system(size: 15, weight: .bold)).foregroundStyle(.white)
                            .frame(width: 32, height: 32)
                            .background(Circle().fill(accent.buttonGradient))
                            .shadow(color: accent.accent.opacity(0.35), radius: 3, y: 2)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(step.title).font(.system(size: 15.5, weight: .semibold))
                            Text(step.body).font(.system(size: 13.5)).foregroundStyle(Tok.secondary).lineSpacing(2)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer(minLength: 8)
                        Sym(step.icon, size: 22).foregroundStyle(Tok.tertiary)
                    }
                    .padding(.horizontal, 20).padding(.vertical, 18)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(
                        RoundedRectangle(cornerRadius: Tok.rCard, style: .continuous).fill(Color.white)
                            .overlay(RoundedRectangle(cornerRadius: Tok.rCard, style: .continuous).strokeBorder(Tok.separator, lineWidth: 0.5))
                    )
                    .cardShadow()
                }
            }
            .padding(.top, 26)

            HStack(spacing: 10) {
                PrimaryButton(label: "Replay the guided tour", icon: "wand-sparkles") { model.startTour() }
                GlassButton(label: "Open Hunt", icon: "target") { model.go(.hunt) }
            }
            .padding(.top, 22)
        }
        .frame(maxWidth: 800, alignment: .leading)
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 40).padding(.top, 40).padding(.bottom, 60)
    }
}

// MARK: - Tools Doctor

struct DoctorView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .bottom) {
                VStack(alignment: .leading, spacing: 5) {
                    Text("Tools Doctor").font(.system(size: 24, weight: .bold)).tracking(-0.5)
                    Text("Kali toolchain readiness and capability requirements.")
                        .font(.system(size: 14)).foregroundStyle(Tok.secondary)
                }
                Spacer()
                GlassButton(label: "Re-check", icon: "refresh-cw") {}
            }

            HStack(spacing: 12) {
                summaryTile(number: "7", label: "Ready", color: Tok.green, tinted: true)
                summaryTile(number: "3", label: "Needs setup", color: Tok.orange, tinted: true)
                summaryTile(number: "Kali", label: "Dev Container active", color: Tok.label, tinted: false)
            }
            .padding(.top, 20)

            VStack(spacing: 0) {
                ForEach(Array(DemoData.doctor.enumerated()), id: \.element.id) { i, item in
                    if i > 0 { Rectangle().fill(Tok.separator).frame(height: 0.5) }
                    HStack(spacing: 13) {
                        IconChip(icon: item.icon, size: 30, iconSize: 16, background: AnyShapeStyle(item.chip), radius: Tok.rButtonSm, specular: false)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(item.name).font(.system(size: 14, weight: .semibold))
                            Text(item.cap).font(Tok.monoFont(12)).foregroundStyle(Tok.secondary)
                        }
                        Spacer()
                        statusPill(ok: item.ok, text: item.status)
                    }
                    .padding(.horizontal, 18).padding(.vertical, 13)
                }
            }
            .padding(.top, 16)
            .background(
                RoundedRectangle(cornerRadius: Tok.rCard, style: .continuous).fill(Color.white)
                    .overlay(RoundedRectangle(cornerRadius: Tok.rCard, style: .continuous).strokeBorder(Tok.separator, lineWidth: 0.5))
                    .padding(.top, 16)
            )
            .cardShadow()
        }
        .frame(maxWidth: 820, alignment: .leading)
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 40).padding(.top, 34).padding(.bottom, 60)
    }

    private func summaryTile(number: String, label: String, color: Color, tinted: Bool) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(number).font(.system(size: 30, weight: .bold)).foregroundStyle(tinted ? color : Tok.label)
            Text(label).font(.system(size: 12.5, weight: .medium)).foregroundStyle(Tok.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: Tok.rCard, style: .continuous)
                .fill(tinted
                      ? AnyShapeStyle(LinearGradient(colors: [color.opacity(0.1), color.opacity(0.03)], startPoint: .top, endPoint: .bottom))
                      : AnyShapeStyle(Color.white))
                .overlay(RoundedRectangle(cornerRadius: Tok.rCard, style: .continuous)
                    .strokeBorder(tinted ? color.opacity(0.24) : Tok.separator, lineWidth: 0.5))
        )
    }

    private func statusPill(ok: Bool, text: String) -> some View {
        HStack(spacing: 4) {
            Sym(ok ? "check" : "download", size: 12)
            Text(text).font(.system(size: 11.5, weight: .semibold))
        }
        .foregroundStyle(ok ? Tok.goodFg : Tok.warnFg)
        .padding(.horizontal, 10).padding(.vertical, 3)
        .background(RoundedRectangle(cornerRadius: Tok.rPill).fill(ok ? Tok.goodBg : Tok.warnBg))
    }
}

// MARK: - Engagements

struct EngagementsView: View {
    private let columns = [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .bottom) {
                VStack(alignment: .leading, spacing: 5) {
                    Text("Engagements").font(.system(size: 24, weight: .bold)).tracking(-0.5)
                    Text("Portable authorization records and their hash-chained audit timeline.")
                        .font(.system(size: 14)).foregroundStyle(Tok.secondary)
                }
                Spacer()
                PrimaryButton(label: "New engagement", icon: "plus") {}
            }

            LazyVGrid(columns: columns, spacing: 12) {
                ForEach(DemoData.engagements) { e in engagementCard(e) }
            }
            .padding(.top, 20)

            Text("Audit timeline · local-lab").font(.system(size: 13, weight: .semibold)).foregroundStyle(Tok.secondary)
                .padding(.leading, 2).padding(.top, 20)

            VStack(spacing: 0) {
                ForEach(Array(DemoData.audit.enumerated()), id: \.element.id) { i, a in
                    if i > 0 { Rectangle().fill(Tok.separator).frame(height: 0.5) }
                    HStack(spacing: 13) {
                        IconChip(icon: a.icon, size: 26, iconSize: 14, background: AnyShapeStyle(a.chip), radius: Tok.rPill, specular: false)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(a.action).font(.system(size: 13, weight: .semibold))
                            Text(a.hash).font(Tok.monoFont(11.5)).foregroundStyle(Tok.secondary).lineLimit(1).truncationMode(.tail)
                        }
                        Spacer()
                        Text(a.time).font(Tok.monoFont(11.5)).foregroundStyle(Tok.tertiary)
                    }
                    .padding(.horizontal, 18).padding(.vertical, 12)
                }
            }
            .padding(.top, 10)
            .background(
                RoundedRectangle(cornerRadius: Tok.rCard, style: .continuous).fill(Color.white)
                    .overlay(RoundedRectangle(cornerRadius: Tok.rCard, style: .continuous).strokeBorder(Tok.separator, lineWidth: 0.5))
                    .padding(.top, 10)
            )
            .cardShadow()
        }
        .frame(maxWidth: 860, alignment: .leading)
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 40).padding(.top, 34).padding(.bottom, 60)
    }

    private func engagementCard(_ e: DemoData.Engagement) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 9) {
                Circle().fill(e.dot).frame(width: 9, height: 9)
                Text(e.name).font(.system(size: 15, weight: .semibold))
                Spacer()
                Text(e.ref).font(Tok.monoFont(11).weight(.semibold)).foregroundStyle(Tok.secondary)
            }
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 7) { Sym("crosshair", size: 13); Text(e.scope) }
                HStack(spacing: 7) { Sym("file-signature", size: 13); Text(e.auth) }
            }
            .font(.system(size: 12.5)).foregroundStyle(Tok.secondary)
            .padding(.top, 9)

            HStack(spacing: 6) {
                Text(e.attestLabel)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(e.attested ? Tok.goodFg : Tok.warnFg)
                    .padding(.horizontal, 9).padding(.vertical, 3)
                    .background(RoundedRectangle(cornerRadius: Tok.rPill).fill(e.attested ? Tok.goodBg : Tok.warnBg))
                Text("\(e.events) audit events")
                    .font(.system(size: 11, weight: .semibold)).foregroundStyle(Tok.secondary)
                    .padding(.horizontal, 9).padding(.vertical, 3)
                    .background(RoundedRectangle(cornerRadius: Tok.rPill).fill(Color.rgba(120, 120, 128, 0.13)))
            }
            .padding(.top, 12)
        }
        .padding(.horizontal, 18).padding(.vertical, 17)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: Tok.rCard, style: .continuous).fill(Color.white)
                .overlay(RoundedRectangle(cornerRadius: Tok.rCard, style: .continuous).strokeBorder(Tok.separator, lineWidth: 0.5))
        )
        .cardShadow()
    }
}
