package com.example.introtospringsecurity.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS= Arrays.asList(
            new Student(1,"Don Robbie"),
            new Student(2,"Troopz"),
            new Student(3,"DT")
    );

//    The PreAuthorise annotation allows us to create access levels based on user roles for specific methods
//    hasRole("ROLE_") hasAnyRole("ROLE_) hasAuthority("permission") hasAnyAuthority("permission)


    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    public List<Student> getAllStudents() {
        return STUDENTS;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void registerNewStudent(@RequestBody Student student) {
        System.out.println("POST");
        System.out.println(student);
    }

    @DeleteMapping("/{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void deleteStudent(@PathVariable("studentId") Integer studentId){
        System.out.println("DELETE");
        System.out.println(studentId);
    }

    @PutMapping("/{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void updateStudent(@PathVariable("studentId") Integer studentId,@RequestBody Student student) {
            System.out.println("PUT");
        System.out.println(String.format("%s'%s",studentId,student));
    }
}
