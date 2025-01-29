package com.example.demosecurityjwt.runner;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import com.example.demosecurityjwt.entity.Role;
import com.example.demosecurityjwt.enums.ERole;
import com.example.demosecurityjwt.repository.RoleRepository;

@Component
public class RoleInitializer implements CommandLineRunner {

	@Autowired
	private RoleRepository roleRepository;

	@Override
	public void run(String... args) throws Exception {
		initializeRoles();
	}

	private void initializeRoles() {
		
		if (!roleRepository.existsByName(ERole.ROLE_USER)) {
			roleRepository.save(new Role(ERole.ROLE_USER));
		}
		if (!roleRepository.existsByName(ERole.ROLE_ADMIN)) {
			roleRepository.save(new Role(ERole.ROLE_ADMIN));
		}

		}
}
