package com.adiwal.auth;

import com.adiwal.auth.domain.AuthClientDetails;
import com.adiwal.auth.domain.User;
import com.adiwal.auth.enums.Authorities;
import com.adiwal.auth.repository.AuthClientRepository;
import com.adiwal.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Set;

@SpringBootApplication
public class AuthApplication implements CommandLineRunner {

	@Autowired
	UserRepository userRepository;

	@Autowired
	AuthClientRepository authClientRepository;

	@Lazy
	@Autowired
	private PasswordEncoder passwordEncoder;

	public static void main(String[] args) {
		SpringApplication.run(AuthApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		if (this.userRepository.findByUsername("vikas").isEmpty()) {
			User user = new User();
			Set<Authorities> authorities = new HashSet<>();
			authorities.add(Authorities.ROLE_USER);
			user.setUsername("vikas");
			user.setActivated(true);
			user.setAuthorities(authorities);
			user.setPassword(passwordEncoder.encode("root123"));
			this.userRepository.save(user);
		}
		if (this.authClientRepository.findByClientId("vikas").isEmpty()) {
			AuthClientDetails browserClientDetails = new AuthClientDetails();
			browserClientDetails.setClientId("vikas");
			browserClientDetails.setClientSecret(passwordEncoder.encode("vikas"));
			browserClientDetails.setScopes("ui");
			browserClientDetails.setGrantTypes("refresh_token,password");
			authClientRepository.save(browserClientDetails);
		}
	}
}
