package security.securityFrame.member.entity;


import lombok.Getter;
import lombok.Setter;
import security.securityFrame.Auth.role.MemberRole;
import security.securityFrame.helper.audit.BaseEntity;

import javax.persistence.*;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;


@Getter
@Setter
@Entity
public class Member extends BaseEntity implements Principal {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long memberId;

    @Column(nullable = false, unique = true, updatable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    @OneToMany(mappedBy = "member", fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    private List<MemberRole> memberRoles = new ArrayList<>();


    @Override
    public String getName() {
        return null;
    }

    public List<String> getRoles() { // 권한 이름을 리스트로 collect 해줍니다.
        return this.getMemberRoles()
                .stream()
                .map(memberRole -> memberRole.getRole().getName())
                .collect(Collectors.toList());
    }

    public String getRoleName() {
        List<String> roleNames = this.getRoles();

        if (roleNames.contains("PARTNER")) {
            return "PARTNER";
        }

        return "USER";
    }
}
