package com.goodbam.jwtServer.controller;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.goodbam.jwtServer.repository.UserRepository;
import com.goodbam.jwtServer.model.User;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
public class testController {
	
	private final UserRepository userRepository;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@GetMapping(value = "/api/user/test")
	public String user() {
		return "user 접근 완료";
	}
	
	@GetMapping(value = "/api/admin/test")
	public String admin() {
		return "admin 접근 완료";
	}
	
	@PostMapping(value = "/join")
	public String join(@RequestBody User user) {
		
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		user.setRoles("ROLE_USER");
		userRepository.save(user);
		
		return "회원가입 완료";
	}
}
