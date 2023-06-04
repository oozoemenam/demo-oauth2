package com.example.demooauth2.security.oauth2.model;

import com.example.demooauth2.enums.AuthProvider;
import com.example.demooauth2.exception.OAuth2AuthenticationException;
import com.example.demooauth2.security.oauth2.model.FacebookOAuth2UserInfo;
import com.example.demooauth2.security.oauth2.model.GoogleOAuth2UserInfo;
import com.example.demooauth2.security.oauth2.model.OAuth2UserInfo;

import java.util.Map;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if (registrationId.equalsIgnoreCase(AuthProvider.google.toString())) {
            return new GoogleOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase(AuthProvider.facebook.toString())) {
            return new FacebookOAuth2UserInfo(attributes);
        } else {
            throw new OAuth2AuthenticationException("Login with " + registrationId + " is not supported.");
        }
    }
}
