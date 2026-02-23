import Foundation
import Combine

@MainActor
final class GroupChatViewModel: ObservableObject {
    @Published var messages: [GroupMessage] = []
    @Published var isLoading = false
    @Published var errorMessage: String?

    let group: Group
    private var cancellables = Set<AnyCancellable>()

    init(group: Group) {
        self.group = group

        WebSocketService.shared.$incomingGroupMessage
            .compactMap { $0 }
            .filter { $0.groupId == group.id }
            .receive(on: RunLoop.main)
            .sink { [weak self] gm in
                guard let self else { return }
                if !self.messages.contains(where: { $0.id == gm.id }) {
                    self.messages.append(gm)
                }
            }
            .store(in: &cancellables)
    }

    func load() async {
        isLoading = true
        defer { isLoading = false }
        do {
            messages = try await APIService.shared.groupMessages(groupId: group.id)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func send(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        WebSocketService.shared.sendGroupMessage(groupId: group.id, content: trimmed)
    }
}
