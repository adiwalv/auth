package com.adiwal.auth.repository;

import com.adiwal.auth.domain.AccessToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MongoAccessTokenRepository extends MongoRepository<AccessToken, String> {
    Optional<AccessToken> findByTokenId(String tokenId);
    Optional<AccessToken> findByRefreshToken(String refreshToken);
    Optional<AccessToken> findByAuthenticationId(String authenticationId);
}
