/**
 * © Vikas Adiwal (adiwalv@gmail.com) 2020. All rights reserved.
 * CONFIDENTIAL AND PROPRIETARY INFORMATION OF VIKAS ADIWAL.
 */
package com.adiwal.auth.service;

import com.adiwal.auth.repository.AuthClientRepository;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.stereotype.Service;

@Service
public class AuthClientDetailsService implements ClientDetailsService {
    private final AuthClientRepository authClientRepository;

    public AuthClientDetailsService(AuthClientRepository authClientRepository) {
        this.authClientRepository = authClientRepository;
    }

    @Override
    public ClientDetails loadClientByClientId(String clientId) {
        return authClientRepository.findByClientId(clientId).orElseThrow(IllegalArgumentException::new);
    }
}
