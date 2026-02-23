import Foundation
import Combine

struct WSMessage: Decodable {
    let type: String
    let fromUser: Int?
    let toUser: Int?
    let content: String?
    let messageId: Int?
    let users: [WSUser]?

    enum CodingKeys: String, CodingKey {
        case type
        case fromUser  = "from_user"
        case toUser    = "to_user"
        case content
        case messageId = "message_id"
        case users
    }
}

struct WSUser: Decodable {
    let id: Int
    let username: String
    let online: Bool
}

@MainActor
final class WebSocketService: ObservableObject {
    static let shared = WebSocketService()

    @Published var onlineUserIds: Set<Int> = []
    @Published var incomingMessage: Message?
    @Published var typingUsers: Set<Int>    = []
    @Published var isConnected              = false

    private var webSocketTask: URLSessionWebSocketTask?
    private var pingTimer: Timer?

    private init() {}

    func connect() {
        guard let token = KeychainService.load(Config.Keychain.tokenKey) else { return }
        guard let url = URL(string: "\(Config.wsURL)?token=\(token)") else { return }
        let session = URLSession(configuration: .default)
        webSocketTask = session.webSocketTask(with: url)
        webSocketTask?.resume()
        isConnected = true
        receive()
        startPing()
    }

    func disconnect() {
        pingTimer?.invalidate()
        webSocketTask?.cancel(with: .normalClosure, reason: nil)
        webSocketTask = nil
        isConnected   = false
        onlineUserIds = []
    }

    func sendTyping(to userId: Int) {
        let payload: [String: Any] = ["type": "typing", "to_user": userId]
        send(payload)
    }

    func markRead(messageId: Int) {
        let payload: [String: Any] = ["type": "read", "message_id": messageId]
        send(payload)
    }

    private func send(_ dict: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: dict),
              let str  = String(data: data, encoding: .utf8) else { return }
        webSocketTask?.send(.string(str)) { _ in }
    }

    private func receive() {
        webSocketTask?.receive { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let msg):
                if case .string(let text) = msg {
                    Task { @MainActor in self.handle(text) }
                }
                self.receive()
            case .failure:
                Task { @MainActor in
                    self.isConnected = false
                    // Reconnect after 3 s
                    try? await Task.sleep(nanoseconds: 3_000_000_000)
                    self.connect()
                }
            }
        }
    }

    private func handle(_ text: String) {
        guard let data = text.data(using: .utf8),
              let msg  = try? JSONDecoder().decode(WSMessage.self, from: data) else { return }

        switch msg.type {
        case "chat":
            if let from = msg.fromUser, let to = msg.toUser, let content = msg.content, let id = msg.messageId {
                let message = Message(id: id, fromUser: from, toUser: to,
                                      content: content, read: false,
                                      createdAt: ISO8601DateFormatter().string(from: Date()))
                incomingMessage = message
            }
        case "users_list", "user_status":
            if let users = msg.users {
                onlineUserIds = Set(users.filter { $0.online }.map { $0.id })
            }
        case "typing":
            if let from = msg.fromUser {
                typingUsers.insert(from)
                Task {
                    try? await Task.sleep(nanoseconds: 3_000_000_000)
                    await MainActor.run { self.typingUsers.remove(from) }
                }
            }
        default: break
        }
    }

    private func startPing() {
        pingTimer?.invalidate()
        pingTimer = Timer.scheduledTimer(withTimeInterval: 25, repeats: true) { [weak self] _ in
            self?.webSocketTask?.sendPing { _ in }
        }
    }
}
