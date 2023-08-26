package security.securityFrame.Auth.role;


import lombok.Getter;
import lombok.Setter;
import security.securityFrame.member.entity.Member;

import javax.persistence.*;

@Getter
@Setter
@Entity
public class MemberRole {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long memberRoleId;

    @ManyToOne
    @JoinColumn(name = "MEMBER_ID")
    private Member member;

    @ManyToOne
    @JoinColumn(name = "ROLE_ID")
    private Role role;
}
