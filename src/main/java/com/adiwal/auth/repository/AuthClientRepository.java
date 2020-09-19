/**
 * © Vikas Adiwal (adiwalv@gmail.com) 2020. All rights reserved.
 * CONFIDENTIAL AND PROPRIETARY INFORMATION OF VIKAS ADIWAL.
 */
package com.adiwal.auth.repository;

import com.adiwal.auth.domain.AuthClientDetails;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthClientRepository extends MongoRepository<AuthClientDetails, String> {
    Optional<AuthClientDetails> findByClientId(String clientId);
}
