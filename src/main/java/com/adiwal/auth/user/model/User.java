package com.adiwal.auth.user.model;

import java.util.List;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonProperty.Access;

@Data
@Document(collection = "users")
public class User {
	@Id
	private String id;
	private String name;
	private String username;
	@JsonProperty(access = Access.WRITE_ONLY)
	private String password;
	private List<String> roles;
}
