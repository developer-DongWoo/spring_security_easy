package security.securityFrame.member.service;


import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import security.securityFrame.Auth.role.MemberRole;
import security.securityFrame.Auth.role.Role;
import security.securityFrame.Auth.role.RoleService;
import security.securityFrame.exception.BusinessLogicException;
import security.securityFrame.exception.ExceptionCode;
import security.securityFrame.member.entity.Member;
import security.securityFrame.member.repository.MemberRepository;

import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final RoleService roleService;
    private final PasswordEncoder passwordEncoder;
    @Transactional(propagation = Propagation.REQUIRED)
    public Member createMember(Member member) {
        // 이메일, 닉네임, 휴대폰 번호 중복 검사
        verifyExistsEmail(member.getEmail());

        // Password 단방향 암호화
        String encryptedPW = passwordEncoder.encode(member.getPassword());
        member.setPassword(encryptedPW);

        // DB에 User Role 저장
        Role userRole = roleService.findUserRole();
        List<MemberRole> memberRoles = addedMemberRole(member, userRole);
        member.setMemberRoles(memberRoles);

        return memberRepository.save(member);
    }

    private void verifyExistsEmail(String email) {
        Optional<Member> member = memberRepository.findByEmail(email);

        if (member.isPresent()) {
            throw new BusinessLogicException(ExceptionCode.BAD_REQUEST);
        }
    }


    public boolean isExistMember(String email) {
        Optional<Member> member = memberRepository.findByEmail(email);
        return member.isPresent();
    }
    public List<MemberRole> addedMemberRole(Member member, Role role) {
        MemberRole memberRole = new MemberRole();
        memberRole.setMember(member);
        memberRole.setRole(role);

        List<MemberRole> memberRoles = member.getMemberRoles();
        memberRoles.add(memberRole);

        return memberRoles;
    }


    public Member findByMemberId(Long memberId) {
        Optional<Member> findMember = memberRepository.findById(memberId);
        if (findMember.isPresent()) return findMember.get();
        else throw new BusinessLogicException(ExceptionCode.BAD_REQUEST);
    }
}
