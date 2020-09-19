/**
 * © Vikas Adiwal (adiwalv@gmail.com) 2020. All rights reserved.
 * CONFIDENTIAL AND PROPRIETARY INFORMATION OF VIKAS ADIWAL.
 */
package com.adiwal.auth.repository;

import com.adiwal.auth.domain.AccessToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AccessTokenRepository extends MongoRepository<AccessToken, String> {
    Optional<AccessToken> findByTokenId(String tokenId);
    Optional<AccessToken> findByRefreshToken(String refreshToken);
    Optional<AccessToken> findByAuthenticationId(String authenticationId);
}
