package com.ambro.space.controller;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ambro.space.entity.Student;

import jakarta.annotation.PostConstruct;

@RestController
@RequestMapping
public class StudentController {
	
	public static List<Student> students = new ArrayList<Student>();
	
	@PostConstruct
	void loadStudents() {
	}
	
//	@PreAuthorize("hasRole('ADMIN') OR hasRole('USER')")
	@GetMapping
	List<Student> getList(){
		return students;
	}
	
//	@PreAuthorize("hasRole('ADMIN')")
	@PostMapping
	Object addStudent(@RequestBody Student student) {
		students.add(student);
		
		return "Added to list";
	}

}
