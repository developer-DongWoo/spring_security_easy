package security.securityFrame.Auth.role;


import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Entity
@NoArgsConstructor
@Table(name = "ROLES") // 권한테이블 명
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long roleId;

    @Column(nullable = false, unique = true)
    private String name;

    @OneToMany(mappedBy = "role")
    private List<MemberRole> memberRoles = new ArrayList<>(); //권한들을 리스트로 저장

    public Role(String name){
        this.name = name; // 권한 이름
    }
}
