package com.example.users.service.register;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data @AllArgsConstructor
public class  RegistationRequest {
	private String username;
	private String password;
	private String email;
	
}
