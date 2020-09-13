package com.adiwal.auth.security;

import com.adiwal.auth.domain.AccessToken;
import com.adiwal.auth.domain.refreshToken;
import com.adiwal.auth.repository.MongoAccessTokenRepository;
import com.adiwal.auth.repository.MongoRefreshTokenRepository;
import com.adiwal.auth.util.AppConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public class MongoTokenStore implements TokenStore {

    private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();

    @Autowired
    private MongoTemplate mongoTemplate;

    @Autowired
    private MongoAccessTokenRepository mongoAccessTokenRepository;

    @Autowired
    private MongoRefreshTokenRepository mongoRefreshTokenRepository;

    @Override
    public OAuth2Authentication readAuthentication(OAuth2AccessToken accessToken) {
        return readAuthentication(accessToken.getValue());
    }

    @Override
    public OAuth2Authentication readAuthentication(String token) {
        Optional<AccessToken> mongoAccessToken = mongoAccessTokenRepository.findByTokenId(extractTokenKey(token));
        return mongoAccessToken.map(AccessToken::getAuthentication).orElse(null);
    }

    @Override
    public void storeAccessToken(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        String refreshToken = null;
        if (accessToken.getRefreshToken() != null) {
            refreshToken = accessToken.getRefreshToken().getValue();
        }

        if (readAccessToken(accessToken.getValue()) != null) {
            this.removeAccessToken(accessToken);
        }

        AccessToken mongoAccessToken = new AccessToken();
        mongoAccessToken.setTokenId(extractTokenKey(accessToken.getValue()));
        mongoAccessToken.setToken(accessToken);
        mongoAccessToken.setAuthenticationId(authenticationKeyGenerator.extractKey(authentication));
        mongoAccessToken.setUsername(authentication.isClientOnly() ? null : authentication.getName());
        mongoAccessToken.setClientId(authentication.getOAuth2Request().getClientId());
        mongoAccessToken.setAuthentication(authentication);
        mongoAccessToken.setRefreshToken(extractTokenKey(refreshToken));

        mongoAccessTokenRepository.save(mongoAccessToken);
    }

    @Override
    public OAuth2AccessToken readAccessToken(String tokenValue) {
        Optional<AccessToken> mongoAccessToken = mongoAccessTokenRepository.findByTokenId(extractTokenKey(tokenValue));
        return mongoAccessToken.map(AccessToken::getToken).orElse(null);
    }

    @Override
    public void removeAccessToken(OAuth2AccessToken oAuth2AccessToken) {
        Optional<AccessToken> mongoAccessToken = mongoAccessTokenRepository.findByTokenId(extractTokenKey(oAuth2AccessToken.getValue()));
        assert mongoAccessToken.orElse(null) != null;
        mongoAccessTokenRepository.delete(mongoAccessToken.orElse(null));
    }

    @Override
    public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
        com.adiwal.auth.domain.refreshToken token = new refreshToken();
        token.setTokenId(extractTokenKey(refreshToken.getValue()));
        token.setToken(refreshToken);
        token.setAuthentication(authentication);
        mongoRefreshTokenRepository.save(token);
    }

    @Override
    public OAuth2RefreshToken readRefreshToken(String tokenValue) {
        Optional<refreshToken> mongoRefreshToken = mongoRefreshTokenRepository.findByTokenId(extractTokenKey(tokenValue));
        return mongoRefreshToken.map(refreshToken::getToken).orElse(null);
    }

    @Override
    public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken refreshToken) {
        Optional<com.adiwal.auth.domain.refreshToken> mongoRefreshToken = mongoRefreshTokenRepository.findByTokenId(extractTokenKey(refreshToken.getValue()));
        return mongoRefreshToken.map(com.adiwal.auth.domain.refreshToken::getAuthentication).orElse(null);
    }

    @Override
    public void removeRefreshToken(OAuth2RefreshToken refreshToken) {
        Optional<com.adiwal.auth.domain.refreshToken> mongoRefreshToken = mongoRefreshTokenRepository.findByTokenId(extractTokenKey(refreshToken.getValue()));
        assert mongoRefreshToken.orElse(null) != null;
        mongoRefreshTokenRepository.delete(mongoRefreshToken.orElse(null));
    }

    @Override
    public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
        Optional<AccessToken> mongoAccessToken = mongoAccessTokenRepository.findByRefreshToken(extractTokenKey(extractTokenKey(refreshToken.getValue())));
        assert mongoAccessToken.orElse(null) != null;
        mongoAccessTokenRepository.delete(mongoAccessToken.orElse(null));
    }

    @Override
    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        OAuth2AccessToken accessToken = null;
        String authenticationId = authenticationKeyGenerator.extractKey(authentication);

        Query query = new Query();
        query.addCriteria(Criteria.where(AppConstants.AUTHENTICATION_ID).is(authenticationId));

        Optional<AccessToken> mongoAccessToken = mongoAccessTokenRepository.findByAuthenticationId(authenticationId);
        if (mongoAccessToken.isPresent()) {
            accessToken = mongoAccessToken.get().getToken();
            if (accessToken != null && !authenticationId.equals(this.authenticationKeyGenerator.extractKey(this.readAuthentication(accessToken)))) {
                this.removeAccessToken(accessToken);
                this.storeAccessToken(accessToken, authentication);
            }
        }
        return accessToken;
    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String username) {
        return findTokensByCriteria(
                Criteria.where(AppConstants.CLIENT_ID).is(clientId)
                        .and(AppConstants.USER_NAME).is(username));
    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
        return findTokensByCriteria(Criteria.where(AppConstants.CLIENT_ID).is(clientId));
    }

    private Collection<OAuth2AccessToken> findTokensByCriteria(Criteria criteria) {
        Collection<OAuth2AccessToken> tokens = new ArrayList<>();
        Query query = new Query();
        query.addCriteria(criteria);
        List<AccessToken> accessTokens = mongoTemplate.find(query, AccessToken.class);
        for (AccessToken accessToken : accessTokens) {
            tokens.add(accessToken.getToken());
        }
        return tokens;
    }

    private String extractTokenKey(String value) {
        if (value == null) {
            return null;
        } else {
            MessageDigest digest;
            try {
                digest = MessageDigest.getInstance("MD5");
            } catch (NoSuchAlgorithmException var5) {
                throw new IllegalStateException("MD5 algorithm not available.  Fatal (should be in the JDK).");
            }

            try {
                byte[] e = digest.digest(value.getBytes(StandardCharsets.UTF_8.name()));
                return String.format("%032x", new BigInteger(1, e));
            } catch (UnsupportedEncodingException var4) {
                throw new IllegalStateException("UTF-8 encoding not available.  Fatal (should be in the JDK).");
            }
        }
    }
}