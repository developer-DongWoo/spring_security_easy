package security.securityFrame.member.controller;



import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import security.securityFrame.member.dto.SignupDto;
import security.securityFrame.member.dto.SignupResponseDto;
import security.securityFrame.member.entity.Member;
import security.securityFrame.member.mapper.MemberMapper;
import security.securityFrame.member.service.MemberService;

import javax.validation.Valid;

@RestController
@RequestMapping
@AllArgsConstructor
public class SignupController {

    private final MemberMapper memberMapper;
    private final MemberService memberService;
    @PostMapping("/auth/signup")
    public ResponseEntity signup(@Valid @RequestBody SignupDto signupDto){
        Member requestMember = memberMapper.signupDtoToMember(signupDto);
        Member signupMember = memberService.createMember(requestMember);
        SignupResponseDto responseMember = memberMapper.memberToSignupResponseDto(signupMember);
        return new ResponseEntity<>(responseMember, HttpStatus.CREATED);
    }
}
