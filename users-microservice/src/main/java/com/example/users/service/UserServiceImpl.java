package com.example.users.service;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Optional;
import java.util.Random;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.users.entities.Role;
import com.example.users.entities.User;
import com.example.users.repos.RoleRepository;
import com.example.users.repos.UserRepository;
import com.example.users.service.exceptions.EmailAlreadyExistsException;
import com.example.users.service.exceptions.ExpiredTokenException;
import com.example.users.service.exceptions.InvalidTokenException;
import com.example.users.service.register.RegistationRequest;
import com.example.users.service.register.VerificationToken;
import com.example.users.service.register.VerificationTokenRepository;
import com.example.users.util.EmailSender;

import org.springframework.transaction.annotation.Transactional;

@Transactional
@Service
public class UserServiceImpl implements UserService{

	@Autowired
	UserRepository userRep;


	@Autowired
	RoleRepository roleRep;


	@Autowired
	BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
	VerificationTokenRepository verificationTokenRepo;
	
	@Autowired
	EmailSender emailSender;


	@Override
	public User saveUser(User user) {
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		return userRep.save(user);
	}


	@Override
	public User addRoleToUser(String username, String rolename) {
		User usr = userRep.findByUsername(username);
		Role r = roleRep.findByRole(rolename);
		usr.getRoles().add(r);
		return usr;
	}


	@Override
	public Role addRole(Role role) {
		return roleRep.save(role);
	}


	@Override
	public User findUserByUsername(String username) {
		return userRep.findByUsername(username);
	}

	@Override
	public List<User> findAllUsers() {
		return userRep.findAll();
	}
	@Override
	public User registerUser(RegistationRequest request) {
		Optional<User> optionaluser = userRep.findByEmail(request.getEmail());
		if(optionaluser.isPresent())
			throw new EmailAlreadyExistsException("email déjà existant!");
		User newUser = new User();
		newUser.setUsername(request.getUsername());
		newUser.setEmail(request.getEmail());
		newUser.setPassword(bCryptPasswordEncoder.encode(request.getPassword()));
		newUser.setEnabled(false);
		userRep.save(newUser);
		//ajouter à newUser le role par défaut USER
		Role r = roleRep.findByRole("USER");
		List<Role> roles = new ArrayList<>();
		roles.add(r);
		newUser.setRoles(roles);

		userRep.save(newUser);

		//génére le code secret
		String code = this.generateCode();

		VerificationToken token = new VerificationToken(code, newUser);
		verificationTokenRepo.save(token);
		
		//sendEmailUser(newUser,token.getToken());

		return newUser;
	}
	public String generateCode() {
		Random random = new Random();
		Integer code = 100000 + random.nextInt(900000);

		return code.toString();
	}
	@Override
	public void sendEmailUser(User u, String code) {
		 String emailBody ="Bonjour "+ "<h1>"+u.getUsername() +"</h1>" +
		 " Votre code de validation est "+"<h1>"+code+"</h1>";
		emailSender.sendEmail(u.getEmail(), emailBody);
		}
	
	@Override
	public User validateToken(String code) {
		VerificationToken token = verificationTokenRepo.findByToken(code);
		
		if(token == null){
			throw new InvalidTokenException("Invalid Token !!!!!!!");
		}

		User user = token.getUser();
		
		Calendar calendar = Calendar.getInstance();
		
		if ((token.getExpirationTime().getTime() - calendar.getTime().getTime()) <= 0){
			verificationTokenRepo.delete(token);
			throw new ExpiredTokenException("expired Token");
		}
		
		user.setEnabled(true);
		userRep.save(user);
		return user;
	}


}
