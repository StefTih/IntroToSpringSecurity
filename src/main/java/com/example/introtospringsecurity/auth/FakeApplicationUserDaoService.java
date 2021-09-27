package com.example.introtospringsecurity.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.introtospringsecurity.security.ApplicationUserRole.*;

//  This simply tells InteliJ that this class needs to be instantiated and the name is what you use to
//  Autowire in case you have more than one implementation
@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao{

//    To encode the passwords
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

//    This method finds the first username from the DB that equals the credentials entered from the user
//    and stores it in an Optional, else Optional is empty
    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

//    To generate the users
    private List<ApplicationUser> getApplicationUsers() {
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                        "Don",
                        passwordEncoder.encode("Robbie"),
                        STUDENT.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        "Troopz",
                        passwordEncoder.encode("Auba"),
                        ADMIN.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        "DT",
                        passwordEncoder.encode("Behave"),
                        ADMINTRAINEE.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                )
        );
    return applicationUsers;
    }

}
