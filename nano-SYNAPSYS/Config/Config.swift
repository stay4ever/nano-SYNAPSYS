import Foundation

enum Config {
    static let baseURL = "https://www.ai-evolution.com.au"
    static let wsURL   = "wss://www.ai-evolution.com.au/chat"

    enum API {
        static let register      = "\(baseURL)/auth/register"
        static let login         = "\(baseURL)/auth/login"
        static let me            = "\(baseURL)/auth/me"
        static let users         = "\(baseURL)/api/users"
        static let contacts      = "\(baseURL)/api/contacts"
        static let messages      = "\(baseURL)/api/messages"
        static let botChat       = "\(baseURL)/api/bot/chat"
        static let passwordReset = "\(baseURL)/auth/password-reset"
    }

    enum Keychain {
        static let tokenKey      = "nano_synapsys_jwt"
        static let userKey       = "nano_synapsys_user"
        static let privateKeyTag = "com.aievolve.nanosynapsys.ecprivatekey"
    }

    enum App {
        static let name          = "nano-SYNAPSYS"
        static let version       = "1.0.0"
        static let encryptionLabel = "AES-256-GCM · ECDH-P384 · E2E Encrypted"
    }
}
