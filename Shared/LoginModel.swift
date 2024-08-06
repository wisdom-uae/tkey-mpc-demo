import Foundation
import SwiftJWT
import CustomAuth
import CryptoKit
import TorusUtils
import CustomAuth

class LoginModel: ObservableObject {
    @Published var loggedIn: Bool = false
    @Published var isLoading = false
    @Published var navigationTitle: String = ""
    @Published var userData: [String: Any]!

    func setup() async {
        await MainActor.run(body: {
            isLoading = true
            navigationTitle = "Loading"
        })
        await MainActor.run(body: {
            if self.userData != nil {
                loggedIn = true
            }
            isLoading = false
            navigationTitle = loggedIn ? "UserInfo" : "SignIn"
        })
    }

    func readPrivateKey() -> Data? {
        guard let filePath = Bundle.main.path(forResource: "privateKey", ofType: "pem"),
              let keyString = try? String(contentsOfFile: filePath, encoding: .utf8) else {
            return nil
        }
        
        let keyStringTrimmed = keyString
            .replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
        
        return Data(base64Encoded: keyStringTrimmed)
    }
    
    func loginWithCustomAuth() {
        Task {
            let sub = SubVerifierDetails(loginType: .web,
                                         loginProvider: .jwt,
                                         clientId: "BJlz-2NXMALL42MdbuCIR-c-b-FlwTlejYbzoidzelUd8bMJMJYxhw4QDlgtqKwgA_rUG8FrTx8kQjeZ2Phs-CU",
                                         verifier: "backend",
                                         redirectURL: "tdsdk://tdsdk/oauthCallback",
                                         browserRedirectURL: "https://scripts.toruswallet.io/redirect.html")
            let tdsdk = CustomAuth( aggregateVerifierType: .singleLogin, aggregateVerifier: "google-lrc", subVerifierDetails: [sub], network: .sapphire(.SAPPHIRE_DEVNET), enableOneKey: true)
//            let data = try await tdsdk.triggerLogin()
//            print(data)

            let verifier = "backend"
            let verifierID = "faj2720i2fdG7NsqznOKrthDvq12"
            let myHeader = Header(kid: "75d69844f20b41064b70ad")
            struct MyClaims: Claims {
                let iss: String
                let sub: String
                let exp: Date
                let aud:String
                let name :String
                let email:String
                let iat: Date
            }
            let myClaims = MyClaims(
                iss: "https://my-authz-server",
                sub: "faj2720i2fdG7NsqznOKrthDvq12",
                exp: Date(timeIntervalSinceNow: 3600),
                aud: "urn:my-resource-server",
                name: "hahaha",
                email: "bababa",
                iat: Date()
            )
            var myJWT = JWT(header: myHeader, claims: myClaims)
            guard let privateKey = self.readPrivateKey() else {
                print("Failed to read private key")
                return
            }
            let jwtSigner = JWTSigner.rs256(privateKey: privateKey)
            let token = try myJWT.sign(using: jwtSigner)
            print("Generated JWT: \(token)")
            let responseParameters = ["id_token":token]
            let newData = try await sub.getUserInfo(responseParameters: responseParameters)
            let data = newData
            let torusKey = try await tdsdk.getTorusKey(verifier: verifier, verifierId: verifierID, idToken: token, userData: data)
            await MainActor.run(body: {
                self.userData = torusKey
                loggedIn = true
            })
        }
    }

}
