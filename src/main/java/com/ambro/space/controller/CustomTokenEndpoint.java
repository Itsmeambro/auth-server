//package com.ambro.space.controller;
//
//import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
//
//import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.RequestParam;
//import org.springframework.web.bind.annotation.RestController;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.core.Authentication;
//
//@RestController
//public class CustomTokenEndpoint {
//
//    private final AuthenticationManager authenticationManager;
//    private final OAuth2TokenService oAuth2TokenService;
//
//    public CustomTokenEndpoint(AuthenticationManager authenticationManager, OAuth2TokenService oAuth2TokenService) {
//        this.authenticationManager = authenticationManager;
//        this.oAuth2TokenService = oAuth2TokenService;
//    }
//
//    @PostMapping("/oauth2/token")
//    public OAuth2AccessTokenResponse getToken(@RequestParam String username,
//                                              @RequestParam String password,
//                                              @RequestParam String clientId,
//                                              @RequestParam String clientSecret) {
//
//        // Authenticate user
//        Authentication authentication = new OAuth2PasswordAuthenticationToken(username, password);
//        Authentication auth = authenticationManager.authenticate(authentication);
//
//        // Validate client credentials
//        if (!isValidClient(clientId, clientSecret)) {
//            throw new OAuth2Error("invalid_client", "Invalid client credentials", null);
//        }
//
//        // Generate and return the access token
//        return oAuth2TokenService.createAccessTokenResponse(auth);
//    }
//
//    private boolean isValidClient(String clientId, String clientSecret) {
//        // Perform client validation logic here
//        return "client".equals(clientId) && "secret".equals(clientSecret);
//    }
//}