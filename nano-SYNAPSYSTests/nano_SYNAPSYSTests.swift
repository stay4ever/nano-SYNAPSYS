import XCTest
import CryptoKit
@testable import nano_SYNAPSYS

final class EncryptionServiceTests: XCTestCase {

    // MARK: - Symmetric encrypt / decrypt round-trip

    func test_encryptDecrypt_roundTrip() throws {
        let key       = SymmetricKey(size: .bits256)
        let plaintext = "Hello, nano-SYNAPSYS!"

        let ciphertext = try EncryptionService.encrypt(plaintext, using: key)
        XCTAssertTrue(ciphertext.hasPrefix("ENC:"), "Encrypted output must have ENC: prefix")
        XCTAssertNotEqual(ciphertext, plaintext)

        let recovered = try EncryptionService.decrypt(ciphertext, using: key)
        XCTAssertEqual(recovered, plaintext)
    }

    func test_decrypt_plaintext_passthrough() throws {
        let key   = SymmetricKey(size: .bits256)
        let plain = "not encrypted"
        let result = try EncryptionService.decrypt(plain, using: key)
        XCTAssertEqual(result, plain, "Non-ENC: string should pass through unchanged")
    }

    func test_decrypt_wrongKey_throws() {
        let key1 = SymmetricKey(size: .bits256)
        let key2 = SymmetricKey(size: .bits256)
        let ciphertext = try? EncryptionService.encrypt("secret", using: key1)
        XCTAssertNotNil(ciphertext)
        XCTAssertThrowsError(try EncryptionService.decrypt(ciphertext!, using: key2),
                             "Decrypting with wrong key must throw")
    }

    func test_encryptDecrypt_emptyString() throws {
        let key    = SymmetricKey(size: .bits256)
        let result = try EncryptionService.encrypt("", using: key)
        let back   = try EncryptionService.decrypt(result, using: key)
        XCTAssertEqual(back, "")
    }

    func test_encryptDecrypt_unicode() throws {
        let key       = SymmetricKey(size: .bits256)
        let plaintext = "Héllo wörld 🔐 — nano-SYNAPSYS"
        let back      = try EncryptionService.decrypt(
            try EncryptionService.encrypt(plaintext, using: key),
            using: key
        )
        XCTAssertEqual(back, plaintext)
    }

    // MARK: - ECDH key exchange

    func test_ecdhKeyExchange_producesSharedKey() throws {
        let alice = EncryptionService.generateKeyPair()
        let bob   = EncryptionService.generateKeyPair()

        let aliceShared = try EncryptionService.deriveSharedKey(
            myPrivateKey: alice,
            theirPublicKeyData: EncryptionService.publicKeyData(from: bob)
        )
        let bobShared = try EncryptionService.deriveSharedKey(
            myPrivateKey: bob,
            theirPublicKeyData: EncryptionService.publicKeyData(from: alice)
        )

        let aliceBytes = aliceShared.withUnsafeBytes { Data($0) }
        let bobBytes   = bobShared.withUnsafeBytes   { Data($0) }
        XCTAssertEqual(aliceBytes, bobBytes, "ECDH must produce the same shared secret on both sides")
    }

    func test_ecdhCrossEncrypt_aliceToBob() throws {
        let alice = EncryptionService.generateKeyPair()
        let bob   = EncryptionService.generateKeyPair()

        let sharedA = try EncryptionService.deriveSharedKey(
            myPrivateKey: alice,
            theirPublicKeyData: EncryptionService.publicKeyData(from: bob)
        )
        let sharedB = try EncryptionService.deriveSharedKey(
            myPrivateKey: bob,
            theirPublicKeyData: EncryptionService.publicKeyData(from: alice)
        )

        let msg       = "Top secret message"
        let encrypted = try EncryptionService.encrypt(msg, using: sharedA)
        let decrypted = try EncryptionService.decrypt(encrypted, using: sharedB)
        XCTAssertEqual(decrypted, msg)
    }

    // MARK: - Public key serialisation

    func test_publicKey_serialisationRoundTrip() throws {
        let key     = EncryptionService.generateKeyPair()
        let rawData = EncryptionService.publicKeyData(from: key)
        XCTAssertFalse(rawData.isEmpty)
        let restored = try P384.KeyAgreement.PublicKey(rawRepresentation: rawData)
        XCTAssertEqual(key.publicKey.rawRepresentation, restored.rawRepresentation)
    }
}


// MARK: -

final class KeychainServiceTests: XCTestCase {

    private let testKey = "nano_test_keychain_\(UUID().uuidString)"

    override func tearDown() {
        KeychainService.delete(testKey)
        super.tearDown()
    }

    func test_saveAndLoad_string() {
        let value = "jwt-token-abc123"
        XCTAssertTrue(KeychainService.save(value, for: testKey))
        XCTAssertEqual(KeychainService.load(testKey), value)
    }

    func test_overwrite_updatesValue() {
        KeychainService.save("first",  for: testKey)
        KeychainService.save("second", for: testKey)
        XCTAssertEqual(KeychainService.load(testKey), "second")
    }

    func test_delete_removesValue() {
        KeychainService.save("to-delete", for: testKey)
        XCTAssertTrue(KeychainService.delete(testKey))
        XCTAssertNil(KeychainService.load(testKey))
    }

    func test_loadMissingKey_returnsNil() {
        XCTAssertNil(KeychainService.load("nano_nonexistent_\(UUID().uuidString)"))
    }

    func test_saveAndLoad_data() {
        let data = Data([0x00, 0xFF, 0xAB, 0xCD])
        XCTAssertTrue(KeychainService.saveData(data, for: testKey))
        XCTAssertEqual(KeychainService.loadData(testKey), data)
    }

    func test_saveAndLoad_symmetricKey() {
        let key   = SymmetricKey(size: .bits256)
        let bytes = key.withUnsafeBytes { Data($0) }
        KeychainService.saveData(bytes, for: testKey)
        guard let loaded = KeychainService.loadData(testKey) else {
            return XCTFail("Expected data in keychain")
        }
        let restored = SymmetricKey(data: loaded)
        let restoredBytes = restored.withUnsafeBytes { Data($0) }
        XCTAssertEqual(bytes, restoredBytes)
    }
}


// MARK: -

final class ModelCodingTests: XCTestCase {

    // MARK: AppUser

    func test_appUser_decode() throws {
        let json = """
        {
            "id": 42,
            "username": "alice",
            "email": "alice@test.com",
            "display_name": "Alice",
            "is_approved": true,
            "online": true
        }
        """.data(using: .utf8)!
        let user = try JSONDecoder().decode(AppUser.self, from: json)
        XCTAssertEqual(user.id,          42)
        XCTAssertEqual(user.username,    "alice")
        XCTAssertEqual(user.displayName, "Alice")
        XCTAssertTrue(user.isApproved)
        XCTAssertTrue(user.isOnline ?? false)
    }

    func test_appUser_initialsFromDisplayName() {
        let user = AppUser(id: 1, username: "jd", email: "jd@test.com",
                           displayName: "John Doe", isApproved: true)
        XCTAssertEqual(user.initials, "JD")
    }

    func test_appUser_initialsFromUsername_whenNoDisplayName() {
        let user = AppUser(id: 1, username: "alice", email: "a@test.com",
                           displayName: nil, isApproved: true)
        XCTAssertEqual(user.initials, "AL")
    }

    func test_appUser_namePreference() {
        let withDisplay = AppUser(id: 1, username: "usr", email: "e@t.com",
                                  displayName: "Display Name", isApproved: true)
        XCTAssertEqual(withDisplay.name, "Display Name")

        let noDisplay = AppUser(id: 2, username: "usr", email: "e@t.com",
                                displayName: nil, isApproved: true)
        XCTAssertEqual(noDisplay.name, "usr")
    }

    // MARK: Message

    func test_message_decode() throws {
        let json = """
        {
            "id": 7,
            "from_user": 1,
            "to_user": 2,
            "content": "Hello!",
            "read": false,
            "created_at": "2025-01-15T10:30:00.000Z"
        }
        """.data(using: .utf8)!
        let msg = try JSONDecoder().decode(Message.self, from: json)
        XCTAssertEqual(msg.id,       7)
        XCTAssertEqual(msg.fromUser, 1)
        XCTAssertEqual(msg.content,  "Hello!")
        XCTAssertFalse(msg.read)
    }

    func test_message_encode() throws {
        let req   = SendMessageRequest(toUser: 5, content: "Hi there")
        let data  = try JSONEncoder().encode(req)
        let dict  = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertEqual(dict["to_user"] as? Int,    5)
        XCTAssertEqual(dict["content"] as? String, "Hi there")
    }

    // MARK: Contact

    func test_contact_decode() throws {
        let json = """
        {
            "id": 3,
            "requester_id": 10,
            "receiver_id": 20,
            "status": "accepted",
            "created_at": "2025-01-01T00:00:00Z"
        }
        """.data(using: .utf8)!
        let contact = try JSONDecoder().decode(Contact.self, from: json)
        XCTAssertEqual(contact.status, .accepted)
        XCTAssertEqual(contact.requesterId, 10)
    }

    // MARK: DisappearTimer

    func test_disappearTimer_intervals() {
        XCTAssertNil(DisappearTimer.off.interval)
        XCTAssertEqual(DisappearTimer.h24.interval,  86400)
        XCTAssertEqual(DisappearTimer.d7.interval,   604800)
        XCTAssertEqual(DisappearTimer.d30.interval,  2592000)
    }

    func test_disappearTimer_allCases_count() {
        XCTAssertEqual(DisappearTimer.allCases.count, 4)
    }
}


// MARK: -

final class ConfigTests: XCTestCase {

    func test_baseURL_isHTTPS() {
        XCTAssertTrue(Config.baseURL.hasPrefix("https://"), "Base URL must use HTTPS")
    }

    func test_wsURL_isWSS() {
        XCTAssertTrue(Config.wsURL.hasPrefix("wss://"), "WebSocket URL must use WSS")
    }

    func test_apiEndpoints_containBaseURL() {
        let endpoints = [
            Config.API.register,
            Config.API.login,
            Config.API.me,
            Config.API.users,
            Config.API.contacts,
            Config.API.messages,
            Config.API.botChat,
        ]
        for ep in endpoints {
            XCTAssertTrue(ep.hasPrefix(Config.baseURL), "Endpoint \(ep) must start with baseURL")
        }
    }

    func test_apiEndpoints_areValidURLs() {
        let endpoints = [
            Config.API.register, Config.API.login, Config.API.me,
            Config.API.users, Config.API.contacts, Config.API.messages, Config.API.botChat,
        ]
        for ep in endpoints {
            XCTAssertNotNil(URL(string: ep), "\(ep) must be a valid URL")
        }
    }

    func test_keychainKeys_areNonEmpty() {
        XCTAssertFalse(Config.Keychain.tokenKey.isEmpty)
        XCTAssertFalse(Config.Keychain.userKey.isEmpty)
        XCTAssertFalse(Config.Keychain.privateKeyTag.isEmpty)
    }

    func test_encryptionLabel_containsAlgorithms() {
        let label = Config.App.encryptionLabel
        XCTAssertTrue(label.contains("AES-256-GCM"), "Label must mention AES-256-GCM")
        XCTAssertTrue(label.contains("ECDH-P384"),   "Label must mention ECDH-P384")
        XCTAssertTrue(label.contains("E2E"),          "Label must mention E2E")
    }
}


// MARK: -

final class BotMessageTests: XCTestCase {

    func test_botMessage_initAssignsFields() {
        let msg = BotMessage(role: .assistant, content: "Hello from Banner")
        XCTAssertEqual(msg.role,    .assistant)
        XCTAssertEqual(msg.content, "Hello from Banner")
        XCTAssertNotNil(msg.id)
    }

    func test_botMessage_uniqueIDs() {
        let a = BotMessage(role: .user,      content: "A")
        let b = BotMessage(role: .assistant, content: "B")
        XCTAssertNotEqual(a.id, b.id)
    }

    func test_botChatRequest_encode() throws {
        let req  = BotChatRequest(message: "What is nano-SYNAPSYS?")
        let data = try JSONEncoder().encode(req)
        let dict = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertEqual(dict["message"] as? String, "What is nano-SYNAPSYS?")
    }
}
