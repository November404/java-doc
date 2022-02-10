## Liunx CentOS8 用户安全设置

- 无操作超时自动登出

  ```shell
  vim /etc/profile
  # 在文章末尾添加，单位秒
  export TMOUT=1800
  source /etc/profile
  ```

- 密码弱口令规则

  ```shell
  vim /etc/security/pwquality.conf
  # 与旧密码不同的字符个数
  difok=3
  # 新密码最小长度
  minlen=8
  # 数字个数。大于0，最多；小于0，最少
  dcredit=-1
  # 大写字母个数。大于0，最多；小于0，最少
  ucredit=-1
  # 小写字母个数。大于0，最多；小于0，最少
  lcredit=-1
  # 特殊字符个数。大于0，最多；小于0，最少
  ocredit=-1
  
  vim /etc/pam.d/system-auth
  # 具体位置见文章末尾
  password    requisite     pam_pwquality.so try_first_pass dcredit=-1 lcredit=-1 ucredit=-1 ocredit=-1 retry=5 minlen=8 difok=3 enforce_for_root
  ```

- 密码有效期设置

  ```shell
  vim /etc/login.defs
  #最近一次密码更新时间+90天 ，即密码过期日期
  PASS_MAX_DAYS 90
  #最近一次密码更新的日期+0 ，即允许用户更改自己的密码的日期
  PASS_MIN_DAYS  0
  #密码过期前7天，用户登录时会提示修改密码
  PASS_WARN_AGE 7
  ```

- 输入密码错误一定次数锁定账户一定时间

  ```shell
  vim /etc/pam.d/system-auth 和 /etc/pam.d/password-auth
  # deny错误的次数 unlock_time锁定时间单位秒 具体位置见文章末尾
  +auth        required                                     pam_faillock.so preauth audit silent even_deny_root deny=5 unlock_time=300
  +auth        [success=1 default=bad]                      pam_unix.so
  +auth        [default=die]                                pam_faillock.so authfail audit even_deny_root deny=5 unlock_time=300
  +auth        sufficient                                   pam_faillock.so authsucc audit deny=5 unlock_time=300
  +account     required                                     pam_faillock.so
  ```

#### System-auth和password-auth格式样例

```shell
/etc/pam.d/password-auth

auth        required                                     pam_env.so
+auth        required                                     pam_faillock.so preauth audit silent even_deny_root deny=5 unlock_time=300
auth        required                                     pam_faildelay.so delay=2000000
auth        [default=1 ignore=ignore success=ok]         pam_succeed_if.so uid >= 1000 quiet
auth        [default=1 ignore=ignore success=ok]         pam_localuser.so
auth        sufficient                                   pam_unix.so nullok try_first_pass
+auth        [success=1 default=bad]                      pam_unix.so
+auth        [default=die]                                pam_faillock.so authfail audit even_deny_root deny=5 unlock_time=300
+auth        sufficient                                   pam_faillock.so authsucc audit deny=5 unlock_time=300
auth        requisite                                    pam_succeed_if.so uid >= 1000 quiet_success
auth        sufficient                                   pam_sss.so forward_pass
auth        required                                     pam_deny.so

+account     required                                     pam_faillock.so
account     required                                     pam_unix.so
account     sufficient                                   pam_localuser.so
account     sufficient                                   pam_succeed_if.so uid < 1000 quiet
account     [default=bad success=ok user_unknown=ignore] pam_sss.so
account     required                                     pam_permit.so

password    requisite                                    pam_pwquality.so try_first_pass local_users_only
password    sufficient                                   pam_unix.so sha512 shadow nullok try_first_pass use_authtok
password    sufficient                                   pam_sss.so use_authtok
password    required                                     pam_deny.so

session     optional                                     pam_keyinit.so revoke
session     required                                     pam_limits.so
-session    optional                                     pam_systemd.so
session     [success=1 default=ignore]                   pam_succeed_if.so service in crond quiet use_uid
session     required                                     pam_unix.so
session     optional                                     pam_sss.so
```

```shell
/etc/pam.d/system-auth

auth        required                                     pam_env.so
+auth        required                                     pam_faillock.so preauth audit silent even_deny_root deny=5 unlock_time=300
auth        required                                     pam_faildelay.so delay=2000000
auth        [default=1 ignore=ignore success=ok]         pam_succeed_if.so uid >= 1000 quiet
auth        [default=1 ignore=ignore success=ok]         pam_localuser.so
auth        sufficient                                   pam_unix.so nullok try_first_pass
+auth        [success=1 default=bad]                      pam_unix.so
+auth        [default=die]                                pam_faillock.so authfail audit even_deny_root deny=5 unlock_time=300
+auth        sufficient                                   pam_faillock.so authsucc audit deny=5 unlock_time=300
auth        requisite                                    pam_succeed_if.so uid >= 1000 quiet_success
auth        sufficient                                   pam_sss.so forward_pass
auth        required                                     pam_deny.so

+account     required                                     pam_faillock.so
account     required                                     pam_unix.so
account     sufficient                                   pam_localuser.so
account     sufficient                                   pam_succeed_if.so uid < 1000 quiet
account     [default=bad success=ok user_unknown=ignore] pam_sss.so
account     required                                     pam_permit.so

+password    requisite                                    pam_pwquality.so try_first_pass dcredit=-1 lcredit=-1 ucredit=-1 ocredit=-1 retry=5 minlen=8 difok=3 enforce_for_root
#password    requisite                                    pam_pwquality.so try_first_pass local_users_only
password    sufficient                                   pam_unix.so sha512 shadow nullok try_first_pass use_authtok
password    sufficient                                   pam_sss.so use_authtok
password    required                                     pam_deny.so

session     optional                                     pam_keyinit.so revoke
session     required                                     pam_limits.so
-session    optional                                     pam_systemd.so
session     [success=1 default=ignore]                   pam_succeed_if.so service in crond quiet use_uid
session     required                                     pam_unix.so
session     optional                                     pam_sss.so
```

