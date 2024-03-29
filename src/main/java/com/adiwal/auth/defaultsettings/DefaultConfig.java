/**
 * © Vikas Adiwal (adiwalv@gmail.com) 2020. All rights reserved.
 * CONFIDENTIAL AND PROPRIETARY INFORMATION OF VIKAS ADIWAL.
 */
package com.adiwal.auth.defaultsettings;

import com.adiwal.auth.domain.AuthClientDetails;
import com.adiwal.auth.repository.AuthClientRepository;
import com.adiwal.auth.repository.UserRepository;
import com.adiwal.commons.domain.User;
import com.adiwal.commons.enums.Authorities;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.HashSet;
import java.util.Set;

@Slf4j
@Service
public class DefaultConfig {

    @Value("${config.user.superuser}")
    private String superUser;

    @Value("${config.user.superuserpassword}")
    private String superUserPassword;

    @Value("${config.user.superuseremail}")
    private String superuseremail;

    @Value("${config.client.rootclient}")
    private String rootClient;

    @Value("${config.client.rootclientpassword}")
    private String rootClientPassword;

    @Value("${config.client.userclient}")
    private String userClient;

    @Value("${config.client.userclientpassword}")
    private String userClientPassword;

    @Value("${config.resetmongo}")
    private boolean resetMongo;

    @Autowired
    UserRepository userRepository;

    @Autowired
    AuthClientRepository authClientRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostConstruct
    public void init() {
        if (resetMongo) {
            userRepository.deleteAll();
            authClientRepository.deleteAll();
        }
        createDefaultUsers();
    }

    public void createDefaultUsers () {
        if (this.userRepository.findByUsername(superUser).isEmpty()) {
            log.info("Trying creating user : {}", superUser);
            User user = new User();
            Set<Authorities> authorities = new HashSet<>();
            authorities.add(Authorities.ROLE_ADMIN);
            user.setUsername(superUser);
            user.setEmail(superuseremail);
            user.setPassword(passwordEncoder.encode(superUserPassword));
            user.setActivated(true);
            user.setAuthorities(authorities);
            this.userRepository.save(user);
            log.info("User {} created!", superUser);
        }
        if (this.authClientRepository.findByClientId(rootClient).isEmpty()) {
            log.info("Trying creating client : {}", rootClient);
            AuthClientDetails browserClientDetails = new AuthClientDetails();
            browserClientDetails.setClientId(rootClient);
            browserClientDetails.setClientSecret(passwordEncoder.encode(rootClientPassword));
            browserClientDetails.setScopes("server");
            browserClientDetails.setGrantTypes("refresh_token,password");
            authClientRepository.save(browserClientDetails);
            log.info("Client {} created!", rootClient);
        }
        if (this.authClientRepository.findByClientId(userClient).isEmpty()) {
            log.info("Trying creating client : {}", userClient);
            AuthClientDetails browserClientDetails = new AuthClientDetails();
            browserClientDetails.setClientId(userClient);
            browserClientDetails.setClientSecret(passwordEncoder.encode(userClientPassword));
            browserClientDetails.setScopes("ui");
            browserClientDetails.setGrantTypes("refresh_token,password");
            authClientRepository.save(browserClientDetails);
            log.info("Client {} created!", userClient);
        }
    }

}
