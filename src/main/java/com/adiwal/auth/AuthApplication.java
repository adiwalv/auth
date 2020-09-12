package com.adiwal.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Arrays;

import com.adiwal.auth.user.model.User;
import com.adiwal.auth.user.repository.UserRepository;

@SpringBootApplication
public class AuthApplication implements CommandLineRunner {
	@Autowired
	private UserRepository userRepository;

	@Lazy
	@Autowired
	private PasswordEncoder passwordEncoder;


	public static void main(String[] args) {
		SpringApplication.run(AuthApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		if (this.userRepository.findByUsername("vikas") == null) {
			User user = new User("Vikas Adiwal", "vikas", passwordEncoder.encode("root123"), Arrays.asList("ADMIN"));

			this.userRepository.save(user);
		}
	}

}
