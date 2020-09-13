package com.adiwal.auth.security;

import com.adiwal.auth.domain.MongoAccessToken;
import com.adiwal.auth.domain.MongoRefreshToken;
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
        Optional<MongoAccessToken> mongoAccessToken = mongoAccessTokenRepository.findByTokenId(extractTokenKey(token));
        return mongoAccessToken.map(MongoAccessToken::getAuthentication).orElse(null);
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

        MongoAccessToken mongoAccessToken = new MongoAccessToken();
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
        Optional<MongoAccessToken> mongoAccessToken = mongoAccessTokenRepository.findByTokenId(extractTokenKey(tokenValue));
        return mongoAccessToken.map(MongoAccessToken::getToken).orElse(null);
    }

    @Override
    public void removeAccessToken(OAuth2AccessToken oAuth2AccessToken) {
        Optional<MongoAccessToken> mongoAccessToken = mongoAccessTokenRepository.findByTokenId(extractTokenKey(oAuth2AccessToken.getValue()));
        assert mongoAccessToken.orElse(null) != null;
        mongoAccessTokenRepository.delete(mongoAccessToken.orElse(null));
    }

    @Override
    public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
        MongoRefreshToken token = new MongoRefreshToken();
        token.setTokenId(extractTokenKey(refreshToken.getValue()));
        token.setToken(refreshToken);
        token.setAuthentication(authentication);
        mongoRefreshTokenRepository.save(token);
    }

    @Override
    public OAuth2RefreshToken readRefreshToken(String tokenValue) {
        Optional<MongoRefreshToken> mongoRefreshToken = mongoRefreshTokenRepository.findByTokenId(extractTokenKey(tokenValue));
        return mongoRefreshToken.map(MongoRefreshToken::getToken).orElse(null);
    }

    @Override
    public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken refreshToken) {
        Query query = new Query();
        query.addCriteria(Criteria.where(MongoRefreshToken.TOKEN_ID).is(extractTokenKey(refreshToken.getValue())));

        MongoRefreshToken mongoRefreshToken = mongoTemplate.findOne(query, MongoRefreshToken.class);
        return mongoRefreshToken != null ? mongoRefreshToken.getAuthentication() : null;
    }

    @Override
    public void removeRefreshToken(OAuth2RefreshToken refreshToken) {
        Query query = new Query();
        query.addCriteria(Criteria.where(MongoRefreshToken.TOKEN_ID).is(extractTokenKey(refreshToken.getValue())));
        mongoTemplate.remove(query, MongoRefreshToken.class);
    }

    @Override
    public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
        Query query = new Query();
        query.addCriteria(Criteria.where(AppConstants.REFRESH_TOKEN).is(extractTokenKey(refreshToken.getValue())));
        mongoTemplate.remove(query, MongoAccessToken.class);
    }

    @Override
    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        OAuth2AccessToken accessToken = null;
        String authenticationId = authenticationKeyGenerator.extractKey(authentication);

        Query query = new Query();
        query.addCriteria(Criteria.where(AppConstants.AUTHENTICATION_ID).is(authenticationId));

        MongoAccessToken mongoAccessToken = mongoTemplate.findOne(query, MongoAccessToken.class);
        if (mongoAccessToken != null) {
            accessToken = mongoAccessToken.getToken();
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
        List<MongoAccessToken> accessTokens = mongoTemplate.find(query, MongoAccessToken.class);
        for (MongoAccessToken accessToken : accessTokens) {
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