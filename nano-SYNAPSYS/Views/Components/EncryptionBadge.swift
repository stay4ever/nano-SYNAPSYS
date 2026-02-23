import SwiftUI

struct EncryptionBadge: View {
    var compact: Bool = false

    var body: some View {
        HStack(spacing: 5) {
            Image(systemName: "lock.fill")
                .font(.system(size: compact ? 9 : 10))
            Text(compact ? "E2E" : Config.App.encryptionLabel)
                .font(compact ? .monoSmall : .monoCaption)
                .lineLimit(1)
        }
        .foregroundColor(.matrixGreen.opacity(0.8))
        .padding(.horizontal, compact ? 6 : 10)
        .padding(.vertical, compact ? 3 : 5)
        .background(Color.darkGreen.opacity(0.4))
        .overlay(
            Capsule().stroke(Color.matrixGreen.opacity(0.25), lineWidth: 1)
        )
        .clipShape(Capsule())
    }
}
