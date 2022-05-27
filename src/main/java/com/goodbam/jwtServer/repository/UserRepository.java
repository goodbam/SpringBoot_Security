package com.goodbam.jwtServer.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.goodbam.jwtServer.model.User;

public interface UserRepository extends JpaRepository<User, Long>{

	public User findByusername(String username);
}
