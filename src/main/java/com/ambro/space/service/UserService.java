//package com.ambro.space.service;
//
//import java.util.Optional;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.security.crypto.factory.PasswordEncoderFactories;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Service;
//
//import com.ambro.space.entity.Student;
//import com.ambro.space.repository.UserRepo;
//
//@Service
//public class UserService implements UserDetailsService{
//	
//	@Autowired
//	UserRepo repo;
//
//	@Override
//	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//		PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
//		System.out.println(username);
//		Optional<Student> studentOpt = repo.findById((long) 1);
//		if(!studentOpt.isPresent()) {
//			System.out.println("Not present");
//			throw new UsernameNotFoundException("No User");
//		}else {
//			
//		}
//		Student student = studentOpt.get();
//		System.out.println(student.toString());
//		
//		UserDetails details = new User(student.getUsername(), encoder.encode(student.getPassword()), student.getAuthorities());
//		
//		return details;
//	}
//
//}
