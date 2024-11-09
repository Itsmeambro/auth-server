package com.ambro.space.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.web.bind.annotation.RequestMapping;

import com.ambro.space.entity.Student;

@RequestMapping
public interface UserRepo extends JpaRepository<Student, Long>{


}
