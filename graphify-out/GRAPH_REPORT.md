# Graph Report - login-watchdog  (2026-10-27)

## Corpus Check
- Large corpus: 548 files · ~717,676 words. Semantic extraction will be expensive (many Claude tokens). Consider running on a subfolder.

## Summary
- 5753 nodes · 13033 edges · 225 communities (192 shown, 33 thin omitted)
- Extraction: 93% EXTRACTED · 7% INFERRED · 0% AMBIGUOUS · INFERRED: 938 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- Next 번들 0
- 앱 통합 테스트
- DB 테스트(FakeQuery)
- Next 번들 3
- Next 번들 4
- 측정·점검 스크립트
- Flask 앱 진입점·에러 핸들러
- 게시판 프런트 JS
- 기기 쿠키·해시
- 공용 UI 컴포넌트(Next)
- 로그인 제출·탐지
- 이메일 인증
- 계정 잠금 DB
- 공격 현황 화면
- Next 번들 14
- Next 번들 15
- 인시던트 상관분석
- 공격 시뮬레이션
- L4 탐지기(netwatch)
- 방화벽 에이전트
- 네트워크 이벤트 DB
- 로그인·프로필 페이지
- 게시판 페이지
- 회원 세션·봇 차단
- SPA 서빙·CSRF
- Next 번들 25
- 문서 생성 챕터 스크립트
- Next 번들 27
- 일일 리포트·AI 총평
- 측정 공용 함수
- Next 번들 30
- 관리자 계정·로그 삭제
- Next 번들 32
- 관리자 세션 테스트
- 권한 검사·승인 API
- Next 번들 35
- 데모 로그 생성
- Next 번들 37
- GeoIP 조회
- IP 예외(출입증) DB
- tests 40
- Next 번들 41
- scripts 42
- notify 43
- tests 44
- Next 번들 45
- tests 46
- Next 번들 47
- tests 48
- tests 49
- Next 번들 50
- tests 51
- tests 52
- tests 53
- tests 54
- tests 55
- tests 56
- netwatch 57
- web 58
- tests 59
- tests 60
- tests 61
- scripts 62
- db 63
- notify 64
- Next 번들 65
- Next 번들 66
- tests 67
- tests 68
- tests 69
- tests 70
- helpers 71
- db 72
- routes 73
- Next 번들 74
- tests 75
- tests 76
- tests 77
- db 78
- .github 79
- web 80
- tests 81
- .github 82
- routes 83
- tests 84
- tests 85
- db 86
- Next 번들 87
- netwatch 88
- tests 89
- scripts 90
- netwatch 91
- tests 92
- db 93
- scripts 94
- scripts 95
- tests 96
- tests 97
- scripts 98
- tests 99
- db 100
- scripts 101
- tests 102
- docker-compose.yml 103
- Next 번들 104
- tests 105
- tests 106
- db 107
- tests 108
- web 109
- docker-compose.yml 110
- Next 번들 111
- tests 112
- tests 113
- tests 114
- docker-compose.yml 115
- netwatch 116
- tests 117
- Next 번들 118
- Next 번들 119
- security 120
- tests 121
- tests 122
- db 123
- Next 번들 124
- Next 번들 125
- tests 126
- tests 127
- tests 128
- db 129
- db 130
- docker-compose.yml 131
- .github 132
- security 133
- Next 번들 134
- scripts 135
- tests 136
- tests 137
- tests 138
- tests 139
- web 140
- docker-compose.yml 141
- tests 142
- tests 143
- security 144
- tests 145
- tests 146
- tests 147
- tests 148
- db 149
- netwatch 150
- Next 번들 151
- Next 번들 152
- scripts 153
- tests 154
- tests 155
- netwatch 156
- netwatch 157
- Next 번들 158
- tests 159
- Next 번들 160
- Next 번들 161
- Next 번들 162
- web 163
- tests 164
- db 165
- docker-compose.yml 166
- Next 번들 167
- Next 번들 168
- tests 169
- db 170
- docker-compose.yml 171
- docker-compose.yml 172
- netwatch 173
- Next 번들 174
- scripts 175
- tests 176
- tests 177
- tests 178
- tests 179
- tests 180
- tests 181
- tests 182
- vercel.json 183
- docker-compose.yml 184
- docker-compose.mailpit.yml 185
- docker-compose.yml 186
- netwatch 187
- netwatch 188
- netwatch 189
- netwatch 190
- scripts 191
- tests 193
- scripts 194
- tests 195
- netwatch 196
- netwatch 197
- scripts 198
- netwatch 199
- scripts 200
- tests 202
- tests 203
- tests 204
- web 205
- Next 번들 206
- tests 207
- db 208
- scripts 209
- scripts 210
- scripts 211
- tests 212
- tests 213

## God Nodes (most connected - your core abstractions)
1. `_FakeQuery` - 102 edges
2. `get_csrf_token()` - 94 edges
3. `tI()` - 63 edges
4. `ih()` - 56 edges
5. `login_admin_session()` - 56 edges
6. `T()` - 44 edges
7. `it()` - 41 edges
8. `n()` - 40 edges
9. `Scenario` - 39 edges
10. `i()` - 37 edges

## Surprising Connections (you probably didn't know these)
- `command_probe()` --indirect_call--> `close()`  [INFERRED]
  netwatch/attacker/lw.py → tests/track_d/test_i_check_s4.py
- `wrapped_view()` --indirect_call--> `action()`  [INFERRED]
  helpers/auth.py → tests/track_d/test_b_playbooks.py
- `test_forwarded_ipv6_is_also_normalized_and_bad_values_still_fall_back()` --calls--> `get_request_ip()`  [EXTRACTED]
  tests/test_ipv6_prefix.py → helpers/request_utils.py
- `test_request_ip_is_the_block_key_for_ipv6_clients()` --calls--> `get_request_ip()`  [EXTRACTED]
  tests/test_ipv6_prefix.py → helpers/request_utils.py
- `test_admin_account_alert_names_the_target_as_an_admin_account()` --calls--> `send_account_lockout_alert()`  [EXTRACTED]
  tests/test_admin_account_lockout.py → notify/alert.py

## Import Cycles
- None detected.

## Communities (225 total, 33 thin omitted)

### Community 0 - "Next 번들 0"
Cohesion: 0.01
Nodes (85): aF(), aH(), av(), ay(), b7(), cB(), cc(), ch() (+77 more)

### Community 1 - "앱 통합 테스트"
Cohesion: 0.03
Nodes (60): get_csrf_token(), _login_as_member(), _post_incident_resolve(), test_admin_login_failure_over_threshold_triggers_lockout(), test_admin_login_locked_ip_short_circuits_before_checking_credentials(), test_admin_login_success_still_creates_session_when_not_suspicious(), test_api_access_alerts_exactly_when_crossing_threshold(), test_api_access_does_not_alert_again_after_threshold_crossing() (+52 more)

### Community 2 - "DB 테스트(FakeQuery)"
Cohesion: 0.04
Nodes (79): _FakeQuery, test_count_recent_distinct_admin_usernames_dedupes_rows(), test_count_recent_distinct_api_paths_returns_number_of_unique_paths(), test_count_recent_distinct_ips_by_username_dedupes_rows(), test_count_recent_distinct_usernames_dedupes_rows(), test_count_recent_not_found_attempts_returns_count(), test_count_recent_page_access_attempts_returns_count(), test_count_recent_unauthorized_attempts_returns_count() (+71 more)

### Community 3 - "Next 번들 3"
Cohesion: 0.05
Nodes (83): eg(), b9(), c(), p(), ba(), bc(), bd(), bf() (+75 more)

### Community 4 - "Next 번들 4"
Cohesion: 0.04
Nodes (72): a0(), a1(), a2(), a3(), a4(), a5(), a8(), a9() (+64 more)

### Community 5 - "측정·점검 스크립트"
Cohesion: 0.05
Nodes (39): append_rows(), choose_fresh_ip(), edge_prefix(), fill(), format_row(), get_reader(), has_net_scanner_ua(), latest_incident_rules() (+31 more)

### Community 6 - "Flask 앱 진입점·에러 핸들러"
Cohesion: 0.04
Nodes (30): format_kr_time(), handle_csrf_error(), handle_rate_limit_exceeded(), index(), count_recent_distinct_api_paths(), log_api_access(), count_recent_signup_attempts(), get_signup_enabled() (+22 more)

### Community 7 - "게시판 프런트 JS"
Cohesion: 0.07
Nodes (70): boardDetailEl, boardPollIntervalMs, boardPostId, knownCommentCount, approveAccessRequest(), createAdminUser(), deleteAdminUser(), deleteComment() (+62 more)

### Community 8 - "기기 쿠키·해시"
Cohesion: 0.05
Nodes (32): get_device_hash(), hash_secret(), new_device_token(), set_device_cookie(), public_base_url(), _log_timing(), report_internal_error(), run_with_fixed_response_time() (+24 more)

### Community 9 - "공용 UI 컴포넌트(Next)"
Cohesion: 0.10
Nodes (60): Pill(), Column, DataTable(), Props, useFeedback(), AgentStatusBadges(), EVIDENCE, L4BlockCard() (+52 more)

### Community 10 - "로그인 제출·탐지"
Cohesion: 0.04
Nodes (53): _login_form(), login_submit(), count_distinct_admin_usernames(), count_distinct_ips_by_username(), count_distinct_usernames(), get_account_lock_state(), get_ip_lock_state(), is_account_locked() (+45 more)

### Community 11 - "이메일 인증"
Cohesion: 0.04
Nodes (49): _after_send(), confirm(), mask_email(), _rate_limited(), request_email_change(), send_verification(), _change_email(), _flash() (+41 more)

### Community 12 - "계정 잠금 DB"
Cohesion: 0.04
Nodes (33): create_account_lockout(), get_account_lockout_row(), get_active_account_lockout(), list_active_account_lockouts(), list_expired_active_account_lockouts(), promote_account_lockout_permanent(), release_account_lockout(), release_permanent_account_lockout() (+25 more)

### Community 13 - "공격 현황 화면"
Cohesion: 0.07
Nodes (54): Page(), Page(), AttackView(), SeverityBadge(), Chart(), ChartSize, Props, readTheme() (+46 more)

### Community 14 - "Next 번들 14"
Cohesion: 0.14
Nodes (50): a(), b(), c(), d(), c(), o(), E(), ea() (+42 more)

### Community 15 - "Next 번들 15"
Cohesion: 0.09
Nodes (51): A(), B(), k(), C(), D(), g(), h(), f() (+43 more)

### Community 16 - "인시던트 상관분석"
Cohesion: 0.06
Nodes (27): _match_cross_layer_rule(), _match_ordered_rule(), record_net_blocked(), resolve_net_blocked(), consider_early_warning(), execute_approved_request(), reject_pending_request(), _run_pending_action() (+19 more)

### Community 17 - "공격 시뮬레이션"
Cohesion: 0.11
Nodes (32): main(), run(), main(), run(), main(), run(), main(), run() (+24 more)

### Community 18 - "L4 탐지기(netwatch)"
Cohesion: 0.05
Nodes (19): gateway_ip_from_prefix(), has_syn_without_ack(), L4Detector, resolve_sensor_iface(), utc_timestamp(), main(), read_positive_int(), run() (+11 more)

### Community 19 - "방화벽 에이전트"
Cohesion: 0.06
Nodes (15): AgentClient, CommandRunner, FakeRunner, FirewallBackend, _int_env(), IptablesBackend, _is_ip_allowlisted(), main() (+7 more)

### Community 20 - "네트워크 이벤트 DB"
Cohesion: 0.05
Nodes (28): bump_network_event(), count_network_events_by_category(), insert_network_event(), list_recent_network_events(), rate_limit_key(), event(), FakeClient, FakeQuery (+20 more)

### Community 21 - "로그인·프로필 페이지"
Cohesion: 0.08
Nodes (35): Page(), Page(), Page(), Page(), NotFound(), Page(), Page(), Page() (+27 more)

### Community 22 - "게시판 페이지"
Cohesion: 0.07
Nodes (40): Page(), Page(), Page(), Page(), Page(), AdminShell(), logout(), TABS (+32 more)

### Community 23 - "회원 세션·봇 차단"
Cohesion: 0.08
Nodes (26): clear_member_session(), member_login_required(), wrapped_view(), get_request_ip(), is_bot_submission(), api_board_comments_latest(), board_comment_delete(), board_comment_submit() (+18 more)

### Community 24 - "SPA 서빙·CSRF"
Cohesion: 0.06
Nodes (20): apply_script_hashes(), _capture_context(), convert_response(), inline_script_hashes(), is_enabled(), is_spa_request(), _json_safe(), not_found_page() (+12 more)

### Community 25 - "Next 번들 25"
Cohesion: 0.08
Nodes (51): rV(), aG(), aI(), aP(), aT(), ax(), c5(), c9() (+43 more)

### Community 26 - "문서 생성 챕터 스크립트"
Cohesion: 0.10
Nodes (5): call(), _kind_for(), later(), Scenario, _snip()

### Community 27 - "Next 번들 27"
Cohesion: 0.07
Nodes (49): bu(), di(), dn(), ex(), fF(), fH(), fX(), hf() (+41 more)

### Community 28 - "일일 리포트·AI 총평"
Cohesion: 0.07
Nodes (20): build_report(), generate_ai_summary(), main(), attempt_signup(), create_account_data(), fetch_signup_csrf_token(), run(), attempt_create_post() (+12 more)

### Community 29 - "측정 공용 함수"
Cohesion: 0.06
Nodes (25): _cell(), choose_fresh_ip(), choose_t1(), compute_intervals(), fill_command(), first_block_run_at(), format_row(), judge() (+17 more)

### Community 30 - "Next 번들 30"
Cohesion: 0.06
Nodes (45): bq(), dK(), dO(), dq(), dU(), gj(), ld(), os() (+37 more)

### Community 31 - "관리자 계정·로그 삭제"
Cohesion: 0.06
Nodes (17): create_admin(), main(), delete_all(), delete_one(), delete_resolved(), main(), show_summary(), describe_settings() (+9 more)

### Community 32 - "Next 번들 32"
Cohesion: 0.08
Nodes (44): cc(), cd(), cf(), cI(), cp(), cs(), e7(), e9() (+36 more)

### Community 33 - "관리자 세션 테스트"
Cohesion: 0.09
Nodes (39): login_admin_session(), stub_admin_role(), _assert_admin_session_cleared(), test_admin_logout_keeps_the_member_session(), test_approve_records_the_admin_id_from_the_session_lookup(), test_deleted_admin_cannot_call_write_api(), test_deleted_admin_cannot_poll_api_status(), test_deleted_admin_is_sent_back_to_login_from_the_dashboard() (+31 more)

### Community 34 - "권한 검사·승인 API"
Cohesion: 0.08
Nodes (20): require_permission(), api_access_requests_approve(), api_access_requests_reject(), api_security_events_resolve(), api_security_incidents_resolve(), api_ip_exemptions_revoke(), api_permanent_locks_release(), api_recovery_requests_revoke() (+12 more)

### Community 35 - "Next 번들 35"
Cohesion: 0.08
Nodes (38): a(), ac(), aD(), aH(), aQ(), au(), aW(), aY() (+30 more)

### Community 36 - "데모 로그 생성"
Cohesion: 0.11
Nodes (23): add_recovery_records(), admin_decisions(), admin_session(), any_member(), Batch, build_daily_summary(), build_plan(), changed_rows() (+15 more)

### Community 37 - "Next 번들 37"
Cohesion: 0.06
Nodes (40): _0(), _1(), _2(), _5(), _6(), _8(), _9(), aJ() (+32 more)

### Community 38 - "GeoIP 조회"
Cohesion: 0.07
Nodes (25): _fetch_location(), format_location(), get_locations(), lookup_address(), normalize_ip(), _prefix_length(), _FakeResponse, test_format_location_lookup_failed() (+17 more)

### Community 39 - "IP 예외(출입증) DB"
Cohesion: 0.06
Nodes (19): get_active_ip_exemption(), insert_ip_exemption(), list_active_ip_exemptions(), revoke_ip_exemption(), consume_recovery_request(), count_recovery_requests_by_ip(), count_recovery_requests_by_user(), create_recovery_request() (+11 more)

### Community 40 - "tests 40"
Cohesion: 0.07
Nodes (17): FakeRunner, load_lw_module(), run_cli(), test_app_trusts_gateway_forwarded_for(), test_attacker_dockerfile_and_requirements(), test_command_stdout_ends_with_json(), test_compose_defines_fixed_attacker_network(), test_compose_gives_attackers_only_net_raw() (+9 more)

### Community 41 - "Next 번들 41"
Cohesion: 0.06
Nodes (38): d0(), d1(), fk(), gB(), gF(), gG(), gN(), gt() (+30 more)

### Community 42 - "scripts 42"
Cohesion: 0.08
Nodes (7): _as_datetime(), _compare(), _norm(), _Not, _now_iso(), Query, Result

### Community 43 - "notify 43"
Cohesion: 0.07
Nodes (20): _build_message(), configuration_warnings(), _deliver(), _from_domain(), print_configuration_warnings(), _profile_link_line(), send_email_change_confirmation(), send_email_changed_notice() (+12 more)

### Community 44 - "tests 44"
Cohesion: 0.07
Nodes (20): send_playbook_alert(), DummyResponse, FakeClient, FakeUsersTable, _install_fake_mail(), _install_fake_users(), test_bump_session_version_gives_up_after_three_losses(), test_bump_session_version_missing_user() (+12 more)

### Community 45 - "Next 번들 45"
Cohesion: 0.07
Nodes (38): dj(), f(), fY(), ga(), ge(), gh(), gi(), go() (+30 more)

### Community 46 - "tests 46"
Cohesion: 0.07
Nodes (23): _append_matched_rule_rpc(), check_success_login(), _invalidate_sessions_once_per_user(), test_concurrent_rule_claim_still_blocks_without_rerunning(), _ack(), agent_env(), login_env(), retry_env() (+15 more)

### Community 47 - "Next 번들 47"
Cohesion: 0.12
Nodes (38): c6(), cM(), cz(), e(), e4(), fE(), fl(), i0() (+30 more)

### Community 48 - "tests 48"
Cohesion: 0.07
Nodes (15): admin_login(), post(), _post_unlock_admin(), _Recorder, test_admin_account_alert_names_the_target_as_an_admin_account(), test_api_status_includes_active_admin_account_lockouts(), test_count_admin_failures_by_username_uses_admin_log_and_fifteen_minute_window(), test_count_distinct_admin_ips_by_username() (+7 more)

### Community 49 - "tests 49"
Cohesion: 0.06
Nodes (4): test_each_measure_run_holds_its_ip_only_once(), test_first_block_run_at_none_without_usable_record(), test_parse_ts_reads_z_offset_and_short_fraction_as_same_utc_time(), test_parse_ts_returns_none_for_missing_or_bad_value()

### Community 50 - "Next 번들 50"
Cohesion: 0.08
Nodes (37): nz(), ca(), cn(), co(), cr(), da(), t(), de() (+29 more)

### Community 51 - "tests 51"
Cohesion: 0.11
Nodes (27): Account, account(), _Chain, _change(), _flashes(), _log_in(), test_board_pages_are_protected_by_the_same_check(), test_change_requires_csrf_and_login() (+19 more)

### Community 52 - "tests 52"
Cohesion: 0.09
Nodes (23): request_password_reset(), _flash(), _forgot(), logged_in(), _reset(), store(), test_bad_new_password_does_not_use_up_the_link(), test_count_email_tokens_by_ip_filters_ip_and_purpose() (+15 more)

### Community 53 - "tests 53"
Cohesion: 0.08
Nodes (18): read_text(), sensor_compose_block(), test_compose_passes_sensor_environment_and_volumes(), test_compose_uses_fixed_suricata_image_tag(), test_entrypoint_downloads_et_open_only_when_missing(), test_entrypoint_has_lf_line_endings(), test_entrypoint_limits_eve_log_size(), test_entrypoint_picks_interface_by_edge_address() (+10 more)

### Community 54 - "tests 54"
Cohesion: 0.08
Nodes (18): _FakeResponse, FakeSession, MockClient, test_client_ack_posts_contract_body(), test_client_ack_truncates_long_error(), test_client_get_blocks_signs_empty_body(), test_client_heartbeat_wraps_detail_with_agent(), test_process_blocks_ack_failure_keeps_block_and_does_not_report_failed() (+10 more)

### Community 55 - "tests 55"
Cohesion: 0.09
Nodes (15): truncate_output_if_oversized(), FakeClock, make_detector(), test_compose_passes_l4_detector_environment(), test_cooldown_suppresses_duplicate_then_allows_again(), test_distinct_ports_emit_port_scan(), test_event_fields_and_timestamp_format(), test_gateway_and_core_sources_are_excluded() (+7 more)

### Community 56 - "tests 56"
Cohesion: 0.10
Nodes (23): after_temporary_lock(), names(), _stub_correlate_db(), test_account_at_strike_count_promotes_with_self_recovery(), test_account_relocked_after_probation_ended_is_not_promoted_below_strike_count(), test_account_relocked_during_probation_is_promoted_as_admin_only_even_below_strike_count(), test_account_that_does_not_exist_is_not_promoted(), test_account_with_undeliverable_email_is_promoted_as_admin_only() (+15 more)

### Community 57 - "netwatch 57"
Cohesion: 0.12
Nodes (15): base_result(), command_brute(), command_httpflood(), command_login(), command_probe(), command_scan(), command_scanner_ua(), command_synflood() (+7 more)

### Community 58 - "web 58"
Cohesion: 0.07
Nodes (28): echarts, next, react-dom, @types/node, @types/react, @types/react-dom, typescript, dependencies (+20 more)

### Community 59 - "tests 59"
Cohesion: 0.08
Nodes (13): DummyResponse, FakeQueryBuilder, FakeSupabaseClient, test_get_network_block(), test_insert_network_block_duplicate_key(), fake_table(), test_try_acquire_cooldown(), fake_table_insert_duplicate() (+5 more)

### Community 60 - "tests 60"
Cohesion: 0.09
Nodes (14): _build_http_client(), get_client(), _now_iso(), _RetryOnDisconnectTransport, fake_send(), test_get_client_passes_our_http_client_to_supabase(), test_get_is_retried_once_after_a_disconnect(), test_get_is_retried_only_once() (+6 more)

### Community 61 - "tests 61"
Cohesion: 0.10
Nodes (25): get_open_incident(), record_incident(), consider_incident_promotion(), test_critical_incident_promotes_immediately(), test_high_incident_goes_to_approval_queue_by_default(), test_high_incident_is_not_queued_again_when_already_permanently_locked(), test_high_incident_promotes_when_auto_on_high_enabled(), test_medium_incident_and_allowlisted_ip_do_nothing() (+17 more)

### Community 62 - "scripts 62"
Cohesion: 0.09
Nodes (14): attempt_login(), fetch_csrf_token(), main(), run(), call_target_endpoints(), fetch_csrf_token(), log_in(), main() (+6 more)

### Community 63 - "db 63"
Cohesion: 0.06
Nodes (9): count_recent_requests_for_target(), decide_request(), get_pending_request(), get_request(), insert_pending_request(), list_pending_requests(), release_cooldown(), update_network_block_if_status() (+1 more)

### Community 64 - "notify 64"
Cohesion: 0.09
Nodes (15): _safe_print(), send_account_lockout_alert(), send_component_alert(), send_incident_escalation_alert(), send_lockout_alert(), send_macro_pattern_alert(), send_mail_failure_alert(), send_page_access_alert() (+7 more)

### Community 65 - "Next 번들 65"
Cohesion: 0.09
Nodes (31): l(), d6(), d7(), d9(), e(), s(), gl(), gp() (+23 more)

### Community 66 - "Next 번들 66"
Cohesion: 0.19
Nodes (31): cl(), E(), e6(), f7(), fn(), fx(), L(), a() (+23 more)

### Community 67 - "tests 67"
Cohesion: 0.09
Nodes (12): list_recent_connected_net_events_for_login(), _login(), login_ready(), NetworkQuery, test_check_error_allows_normal_login(), test_connected_evidence_blocks_session_and_runs_once(), record(), test_db_query_uses_ip_net_source_connected_types_and_utc_window() (+4 more)

### Community 68 - "tests 68"
Cohesion: 0.09
Nodes (18): fake_smtp(), _login(), login_env(), test_account_lock_shows_recovery_link_without_revealing_permanence(), test_admin_login_from_a_permanently_locked_ip_is_blocked_with_no_recovery_link(), test_errors_during_work_never_leak_as_a_500(), test_exempted_user_failing_once_keeps_the_exemption(), test_exempted_user_failing_repeatedly_loses_the_exemption_without_new_ip_lockout() (+10 more)

### Community 69 - "tests 69"
Cohesion: 0.08
Nodes (10): test_enforce_admin_account_lockout_locks_alerts_records_and_never_promotes(), test_enforce_account_lockout_creates_lockout_then_alerts_then_records_event(), test_enforce_lockout_creates_lockout_then_sends_alert(), fake_insert_security_event(), test_notify_macro_pattern_sends_alert_then_records_medium_event(), test_notify_page_access_sends_alert_then_records_medium_event(), test_notify_unauthorized_access_sends_alert_then_records_medium_event(), test_notify_web_scanning_sends_alert_then_records_medium_event() (+2 more)

### Community 70 - "tests 70"
Cohesion: 0.11
Nodes (18): is_network_event_unpromoted(), mark_network_event_promoted(), promote(), _post(), test_category_mapping_and_metadata(), test_db_errors_are_not_treated_as_success(), test_high_conflict_bumps_existing_event(), test_high_uses_bump_and_medium_uses_common_record() (+10 more)

### Community 71 - "helpers 71"
Cohesion: 0.10
Nodes (14): clear_admin_session(), _load_current_admin(), login_required(), wrapped_view(), _reject_admin_request(), decorator(), wrapped_view(), start_admin_session() (+6 more)

### Community 72 - "db 72"
Cohesion: 0.08
Nodes (13): bump_session_version(), change_user_email(), create_user(), delete_user(), get_user_by_id(), get_user_by_username(), get_user_session_version(), is_email_taken() (+5 more)

### Community 73 - "routes 73"
Cohesion: 0.11
Nodes (12): _attach_locations(), admin_attack(), admin_dashboard(), admin_ops(), api_status(), _api_status_section(), _build_agent_status(), _build_permanent_locks() (+4 more)

### Community 74 - "Next 번들 74"
Cohesion: 0.12
Nodes (28): uA(), az(), eB(), eF(), lD(), lM(), lZ(), n1() (+20 more)

### Community 75 - "tests 75"
Cohesion: 0.17
Nodes (20): check_cross_layer(), _rule_ctx(), _ago_iso(), _event(), _install_rule_fakes(), test_cr01_does_not_count_event_outside_window(), test_cr01_missing_app_intrusion_does_not_match(), test_cr01_requires_recon_before_app_intrusion() (+12 more)

### Community 76 - "tests 76"
Cohesion: 0.10
Nodes (17): judge_early_warning(), _truncate_untrusted(), _base_request(), test_consider_early_warning_does_nothing_when_llm_call_fails(), test_consider_early_warning_does_nothing_when_llm_says_not_risky(), test_consider_early_warning_skips_when_already_pending(), _fail_if_called(), test_execute_approved_request_runs_alert_only_action() (+9 more)

### Community 77 - "tests 77"
Cohesion: 0.14
Nodes (13): FakeResponse, FakeSession, sample_body(), test_sender_attaches_valid_hmac_headers(), test_sender_does_not_retry_4xx(), test_sender_queue_has_upper_limit(), test_sender_retries_5xx_with_exponential_backoff(), test_sender_retries_connection_failure() (+5 more)

### Community 78 - "db 78"
Cohesion: 0.08
Nodes (13): count_security_events(), delete_all_security_events(), delete_resolved_security_events(), delete_security_event(), get_unresolved_security_event(), insert_security_event(), insert_security_event_or_bump(), list_resolved_critical_events_since() (+5 more)

### Community 79 - ".github 79"
Cohesion: 0.07
Nodes (26): concurrency, cancel-in-progress, group, environment, runs-on, steps, name, url (+18 more)

### Community 80 - "web 80"
Cohesion: 0.09
Nodes (21): react, Page(), Page(), Api, ConfirmOptions, ConfirmResult, FeedbackContext, FeedbackProvider() (+13 more)

### Community 81 - "tests 81"
Cohesion: 0.14
Nodes (18): main(), parse_usernames(), block_network(), test_config_errors_happen_before_session_creation(), test_dry_run_uses_no_dns_http_or_session_and_masks_password(), test_duplicate_or_insufficient_usernames_are_rejected(), test_early_lock_or_server_error_fails_and_stops(), test_invalid_header_returns_failure_without_leaking_exception() (+10 more)

### Community 82 - ".github 82"
Cohesion: 0.10
Nodes (25): jobs, suricata, test, web, name, branches, continue-on-error, name (+17 more)

### Community 83 - "routes 83"
Cohesion: 0.12
Nodes (13): mask_username(), email_confirm_form(), email_confirm_submit(), _invalid(), _invalid(), password_forgot_form(), password_forgot_submit(), work() (+5 more)

### Community 84 - "tests 84"
Cohesion: 0.13
Nodes (18): request_block(), row(), _fix_now(), test_request_block_compares_expiry_as_time_not_string(), test_request_block_connected_permanent(), test_request_block_idempotent_if_not_stronger(), test_request_block_rejects_allowlisted_ip(), test_request_block_rejects_ipv6() (+10 more)

### Community 85 - "tests 85"
Cohesion: 0.13
Nodes (26): _confirm(), _request_recovery(), test_concurrent_consume_losing_the_race_does_nothing(), test_confirming_account_recovery_releases_lock_starts_probation_and_notifies(), test_expired_request_is_not_confirmable(), test_get_verify_shows_confirmation_without_consuming_the_token(), test_honeypot_request_is_dropped_but_looks_normal(), test_ip_permanent_lock_with_admin_only_recovery_sends_no_mail() (+18 more)

### Community 86 - "db 86"
Cohesion: 0.08
Nodes (12): count_recent_admin_failures(), count_recent_distinct_admin_usernames(), create_admin_user(), delete_admin_user(), ensure_bootstrap_admin(), get_admin_by_id(), get_admin_id_by_username(), get_admin_role_by_id() (+4 more)

### Community 87 - "Next 번들 87"
Cohesion: 0.11
Nodes (24): a(), eC(), eI(), eM(), fb(), iM(), it(), lf() (+16 more)

### Community 88 - "netwatch 88"
Cohesion: 0.12
Nodes (8): Aggregator, make_event_id(), minute_window_start(), normalized_classtype(), optional_int(), to_event(), utc_datetime(), utc_iso()

### Community 89 - "tests 89"
Cohesion: 0.10
Nodes (12): suricata_alert(), test_aggregator_sends_first_event_immediately(), test_aggregator_updates_same_window_on_tick(), test_compose_has_no_stale_core_subnet(), test_compose_restarts_shipper_unless_stopped(), test_heartbeat_body_contains_required_detail(), test_sign_headers_matches_contract_vector(), test_sign_matches_route_implementation_when_available() (+4 more)

### Community 90 - "scripts 90"
Cohesion: 0.18
Nodes (11): build_chapter(), Builder, find_function(), find_line(), header_comment(), lang_of(), main(), read_lines() (+3 more)

### Community 91 - "netwatch 91"
Cohesion: 0.13
Nodes (5): heartbeat_body(), main(), process_tailer(), Sender, Tailer

### Community 92 - "tests 92"
Cohesion: 0.14
Nodes (16): _retry_failed_steps(), run(), ctx(), fake(), test_mail_return_status(), test_missing_context_skips_only_that_step(), test_missing_function_skipped(), test_net01_integration() (+8 more)

### Community 93 - "db 93"
Cohesion: 0.16
Nodes (11): build_threat_stats(), _compute(), _count_since(), _day_labels(), fetch_raw(), _fetch_rows(), _hourly(), _parse() (+3 more)

### Community 94 - "scripts 94"
Cohesion: 0.10
Nodes (10): ConfigParser, create_test_session(), is_local_host(), is_loopback_address(), print_attempt_result(), print_plan(), print_summary(), send_login_attempt() (+2 more)

### Community 95 - "scripts 95"
Cohesion: 0.13
Nodes (8): local_base_url(), main(), run(), main(), NoRedirect, normalize_host(), positive_seconds(), run()

### Community 96 - "tests 96"
Cohesion: 0.12
Nodes (8): command_for(), events(), main(), reset_between_runs(), seed(), serve(), _app_section(), test_app_overrides_smtp_account_to_empty()

### Community 97 - "tests 97"
Cohesion: 0.16
Nodes (13): test_country_and_username_counts_are_only_for_login_tables(), test_every_column_used_by_the_summary_exists(), test_functions_are_not_callable_with_site_keys(), test_only_counts_are_kept_never_ips_or_usernames(), test_rows_are_never_deleted_before_they_are_summarized(), test_summary_calls_match_the_listed_tables_and_columns(), _columns_of(), _tables_in_schema() (+5 more)

### Community 98 - "scripts 98"
Cohesion: 0.11
Nodes (8): main(), show_active_admin_lockouts(), show_active_lockouts(), unlock_admin(), unlock_all(), unlock_one(), released(), test_main_passes_permanent_option_through_to_the_release()

### Community 99 - "tests 99"
Cohesion: 0.10
Nodes (8): _update_incident(), list_recent_security_events_for_correlation(), _CorrelationQuery, call(), test_correlation_query_filters_ip_utc_window_and_orders_oldest(), test_update_incident_returns_false_when_rule_already_written(), test_update_incident_writes_rule_only_if_absent(), _UpdateQuery

### Community 100 - "db 100"
Cohesion: 0.10
Nodes (10): create_lockout(), get_active_lockout(), get_lockout_row(), list_active_lockouts(), list_expired_active_lockouts(), list_lockouts_between(), list_lockouts_since(), promote_lockout_permanent() (+2 more)

### Community 101 - "scripts 101"
Cohesion: 0.16
Nodes (10): demo_login(), demo_member(), apply_load(), connect(), host_of(), main(), pk_of(), prepare() (+2 more)

### Community 102 - "tests 102"
Cohesion: 0.23
Nodes (16): _login_as(), _post(), test_existing_unlock_api_for_plain_missing_target_is_still_200_false(), test_existing_unlock_apis_answer_409_for_permanent_targets(), test_promote_account_requires_existing_user_and_reports_conflict(), test_promote_ip_locks_as_admin_only_with_reason_and_admin_name(), test_promote_rejects_invalid_ip_allowlisted_ip_and_missing_reason(), test_promote_requires_promote_permanent_lock_permission() (+8 more)

### Community 103 - "docker-compose.yml 103"
Cohesion: 0.11
Nodes (20): networks, gateway, subnet, driver, internal, ipam, ipv4_address, name (+12 more)

### Community 104 - "Next 번들 104"
Cohesion: 0.22
Nodes (20): lm(), ao(), as(), ce(), cy(), ee(), ei(), es() (+12 more)

### Community 105 - "tests 105"
Cohesion: 0.13
Nodes (15): check_and_correlate(), _maybe_escalate(), close_incident_if_configured(), test_check_and_correlate_does_nothing_when_fewer_than_two_distinct_types(), test_check_and_correlate_records_incident_when_two_or_more_distinct_types(), test_check_and_correlate_runs_playbook_when_incident_crosses_escalation_threshold(), test_check_and_correlate_skips_playbook_when_already_escalated(), test_check_and_correlate_skips_playbook_when_below_min_event_types() (+7 more)

### Community 106 - "tests 106"
Cohesion: 0.16
Nodes (10): FakeResponse, _load(), _run_login(), SpaSession, test_bruteforce_sim_fetch_csrf_token_falls_back_to_spa(), test_lw_login_falls_back_to_spa_csrf_and_posts_plain_form(), test_lw_login_reports_error_when_no_token_anywhere(), test_lw_login_uses_html_token_without_extra_request() (+2 more)

### Community 107 - "db 107"
Cohesion: 0.11
Nodes (9): count_recent_distinct_ips_by_username(), count_recent_distinct_usernames(), count_recent_failures(), count_recent_failures_by_username(), list_attempts_between(), list_attempts_by_username(), list_attempts_since(), list_recent_attempts() (+1 more)

### Community 108 - "tests 108"
Cohesion: 0.15
Nodes (13): fake_cc(), _load_lw(), _run(), test_applied_block_and_probe_pass(), test_failed_block_without_applied_at_is_fail(), test_lw_probe_reports_reachable_and_blocked(), close(), test_other_ip_blocked_is_fail() (+5 more)

### Community 109 - "web 109"
Cohesion: 0.11
Nodes (18): compilerOptions, allowJs, esModuleInterop, incremental, isolatedModules, jsx, lib, module (+10 more)

### Community 110 - "docker-compose.yml 110"
Cohesion: 0.11
Nodes (18): container_name, depends_on, env_file, environment, expose, networks, restart, MAIL_BACKEND (+10 more)

### Community 111 - "Next 번들 111"
Cohesion: 0.16
Nodes (17): l6(), aa(), al(), an(), ar(), cb(), cQ(), cw() (+9 more)

### Community 112 - "tests 112"
Cohesion: 0.13
Nodes (6): admin_client(), calls(), _release_count(), test_expired_lock_cleanup_runs_at_most_once_per_interval(), test_interval_zero_cleans_up_on_every_refresh(), test_only_returns_that_table_with_a_single_query()

### Community 113 - "tests 113"
Cohesion: 0.11
Nodes (10): _FakeResult, _ScriptedClient, test_latest_pending_recovery_for_username_joins_users_in_a_single_query(), test_latest_pending_recovery_for_username_none_for_unknown_or_no_request(), test_reserve_recovery_code_attempt_does_not_update_when_already_at_the_limit(), test_reserve_recovery_code_attempt_gives_up_after_repeated_races(), test_reserve_recovery_code_attempt_rereads_and_retries_after_losing_a_race(), test_reserve_recovery_code_attempt_returns_none_when_request_is_no_longer_pending() (+2 more)

### Community 114 - "tests 114"
Cohesion: 0.16
Nodes (8): read_project_file(), test_compose_contains_required_services(), test_compose_exposes_only_gateway_and_mailpit_ui(), test_compose_uses_track_d_network_contract(), test_dockerfile_uses_required_runtime(), test_dockerignore_excludes_local_secrets(), test_env_example_contains_role_a_values(), test_nginx_overwrites_forwarded_for()

### Community 115 - "docker-compose.yml 115"
Cohesion: 0.15
Nodes (17): build, build, build, cap_add, image, profiles, build, context (+9 more)

### Community 116 - "netwatch 116"
Cohesion: 0.12
Nodes (17): AIM_SERVERS, DC_SERVERS, DNP3_CLIENT, DNP3_SERVER, DNS_SERVERS, ENIP_CLIENT, ENIP_SERVER, EXTERNAL_NET (+9 more)

### Community 117 - "tests 117"
Cohesion: 0.12
Nodes (14): send_recovery_email(), test_authentication_failure_is_classified_and_alerted_without_secrets(), test_connection_failure_is_classified_as_connect(), test_console_backend_in_production_is_a_reported_config_failure(), test_console_backend_prints_in_development_but_is_refused_in_production(), test_message_has_date_message_id_and_from_headers(), test_permanent_recipient_refusal_is_reported_as_refused(), test_permanent_refusal_and_success_do_not_raise_failure_alerts() (+6 more)

### Community 118 - "Next 번들 118"
Cohesion: 0.21
Nodes (12): cb(), e(), eb(), hb(), ib(), nb(), ob(), rb() (+4 more)

### Community 119 - "Next 번들 119"
Cohesion: 0.16
Nodes (17): sA(), sB(), sC(), sD(), sE(), sF(), o(), sI() (+9 more)

### Community 120 - "security 120"
Cohesion: 0.16
Nodes (9): _is_stronger(), _isoformat_utc(), _now_utc(), _parse_iso(), request_unblock(), _update_with_version(), test_request_unblock_success_and_failure(), test_unblock_bumps_version() (+1 more)

### Community 121 - "tests 121"
Cohesion: 0.32
Nodes (15): build(), _event(), _incident(), _raw(), test_compound_attackers_need_three_event_types_and_country_is_attached(), test_empty_database_gives_zeroes_and_empty_network_layer(), test_failed_logins_and_404s_count_as_detections(), test_flow_and_country_links_aggregate_counts() (+7 more)

### Community 122 - "tests 122"
Cohesion: 0.12
Nodes (3): environment(), IncidentDB, IncidentQuery

### Community 123 - "db 123"
Cohesion: 0.14
Nodes (8): count_recent_admin_failures_by_username(), count_recent_distinct_admin_ips_by_username(), create_admin_account_lockout(), _cutoff_iso(), get_active_admin_account_lockout(), list_active_admin_account_lockouts(), list_expired_active_admin_account_lockouts(), release_admin_account_lockout()

### Community 124 - "Next 번들 124"
Cohesion: 0.15
Nodes (5): g(), i(), j(), T(), v()

### Community 125 - "Next 번들 125"
Cohesion: 0.14
Nodes (16): be(), bw(), fG(), fn(), fr(), gc(), gk(), lj() (+8 more)

### Community 126 - "tests 126"
Cohesion: 0.19
Nodes (10): ensure_l4_released(), admin(), test_ensure_does_not_request_again_when_nothing_left(), test_ensure_reports_failed_on_db_error(), test_ensure_reports_failed_when_unblock_raises(), test_ensure_requests_unblock_for_active_block(), test_full_release_reports_l4_request(), test_l4_failure_is_reported_even_though_l7_was_released() (+2 more)

### Community 127 - "tests 127"
Cohesion: 0.16
Nodes (8): rule_lines(), sid_from_rule(), test_all_local_rules_start_with_alert(), test_local_rule_sids_are_unique_and_reserved(), test_login_burst_rule_matches_plan(), test_required_local_rule_sids_exist(), test_scanner_user_agent_rule_matches_plan(), test_syn_flood_rule_matches_plan()

### Community 128 - "tests 128"
Cohesion: 0.12
Nodes (3): FakeDB, FakeQuery, stored()

### Community 129 - "db 129"
Cohesion: 0.13
Nodes (7): consume_email_token(), count_email_tokens_by_ip(), create_email_token(), get_email_token_activity(), get_pending_email_token(), get_pending_email_token_for_user(), revoke_email_token()

### Community 130 - "db 130"
Cohesion: 0.14
Nodes (8): close_incident_system(), get_recent_distinct_event_types(), _higher_severity(), list_security_incidents(), mark_incident_escalated(), mark_incident_idle(), _merge_into_existing(), resolve_incident()

### Community 131 - "docker-compose.yml 131"
Cohesion: 0.13
Nodes (15): APP_INTERNAL_URL, EVE_PATH, L4_PATH, NET_AGENT_SECRET, NET_INGEST_SECRET, NET_INGEST_URL, PERMANENT_LOCK_IP_ALLOWLIST, SHIPPER_STALL_SECONDS (+7 more)

### Community 132 - ".github 132"
Cohesion: 0.13
Nodes (14): SUPABASE_ANON_KEY, SUPABASE_URL, jobs, ping-supabase, name, runs-on, steps, cron (+6 more)

### Community 133 - "security 133"
Cohesion: 0.19
Nodes (8): send_permanent_lock_alert(), api_permanent_locks_promote(), _in_probation(), is_ip_allowlisted(), promote_account(), promote_ip(), _record_permanent_lock_event(), test_console_fallback_survives_characters_the_terminal_cannot_encode()

### Community 134 - "Next 번들 134"
Cohesion: 0.34
Nodes (14): c(), d(), h(), S(), T(), i(), l(), m() (+6 more)

### Community 135 - "scripts 135"
Cohesion: 0.13
Nodes (3): get_csrf_token(), LoginHTML, PossibleLoginSuccess

### Community 136 - "tests 136"
Cohesion: 0.20
Nodes (10): release(), test_release_ip_records_history_and_alerts(), test_release_returns_false_and_stays_silent_when_not_permanent(), log(), test_account_release_does_not_request_l4_unblock(), test_failed_release_does_not_request_l4_unblock(), test_ip_release_requests_l4_unblock_once_before_alert(), test_unblock_exception_does_not_break_release() (+2 more)

### Community 137 - "tests 137"
Cohesion: 0.13
Nodes (4): Store, store(), test_ssl_port_uses_smtp_ssl_without_starttls(), __init__()

### Community 138 - "tests 138"
Cohesion: 0.18
Nodes (6): StallFakeClock, test_stall_watch_is_stalled_after_threshold(), test_stall_watch_missing_files_become_stalled(), test_stall_watch_recovers_after_truncation(), test_stall_watch_recovers_when_either_file_grows(), test_stall_watch_uses_most_recent_file_growth()

### Community 139 - "tests 139"
Cohesion: 0.19
Nodes (7): _all_check_ips(), FakeReader, test_check_ranges_include_11_to_99_and_avoid_reserved(), test_choose_fresh_ip_explicit_range_still_works(), test_choose_fresh_ip_moves_to_lower_range_when_111_139_used(), test_choose_fresh_ip_prefers_original_range_first(), test_choose_fresh_ip_returns_none_when_all_ranges_used()

### Community 140 - "web 140"
Cohesion: 0.15
Nodes (13): AGENTS, AgentHeartbeat, AgentName, AgentStatus, Attempt, IpRow, Lockout, NetworkBlock (+5 more)

### Community 141 - "docker-compose.yml 141"
Cohesion: 0.15
Nodes (14): EVE_MAX_BYTES, L4_MAX_BYTES, LW_EDGE_PREFIX, SENSOR_IFACE, environment, cap_add, depends_on, entrypoint (+6 more)

### Community 142 - "tests 142"
Cohesion: 0.18
Nodes (6): client(), flask_app(), _stub_permanent_lock_defaults(), _stub_track_d_dashboard_queries(), test_host_argument_is_not_accepted(), test_synflood_limit_rejects_more_than_5000()

### Community 143 - "tests 143"
Cohesion: 0.16
Nodes (9): redact_json(), safe_location(), validate_response(), make_response(), test_json_echo_of_quoted_password_is_redacted(), test_missing_csrf_prevents_any_login_post(), test_response_preview_is_bounded_and_json_is_parsed(), test_response_validation_keeps_detection_indicators_separate() (+1 more)

### Community 144 - "security 144"
Cohesion: 0.25
Nodes (11): _block_l4(), _block_l4_ttl(), _invalidate_sessions(), _llm_postmortem(), _lock_account_permanent(), _lock_ip_permanent(), _MissingContext, _notify_owner_email() (+3 more)

### Community 145 - "tests 145"
Cohesion: 0.14
Nodes (5): calls(), record(), _Chain, fake_client(), incident_env()

### Community 146 - "tests 146"
Cohesion: 0.15
Nodes (12): _code_message(), _submit_code(), test_account_recovery_code_from_another_device_is_rejected_without_using_attempts(), test_code_for_ip_recovery_from_another_device_is_not_checked_and_not_counted(), test_code_for_unknown_user_gives_generic_failure(), test_code_is_not_compared_when_no_attempt_can_be_reserved(), test_concurrent_wrong_codes_cannot_exceed_the_attempt_limit(), test_correct_code_completes_account_recovery() (+4 more)

### Community 148 - "tests 148"
Cohesion: 0.16
Nodes (4): admin_client(), alerts(), setup_env(), test_alert_failure_does_not_break_status()

### Community 149 - "db 149"
Cohesion: 0.15
Nodes (6): count_recent_not_found_attempts(), count_recent_page_access_attempts(), count_recent_unauthorized_attempts(), log_not_found_attempt(), log_page_access_attempt(), log_unauthorized_attempt()

### Community 151 - "Next 번들 151"
Cohesion: 0.41
Nodes (12): c(), d(), F(), h(), i(), l(), m(), n() (+4 more)

### Community 152 - "Next 번들 152"
Cohesion: 0.54
Nodes (12): a(), c(), d(), g(), h(), i(), l(), n() (+4 more)

### Community 153 - "scripts 153"
Cohesion: 0.29
Nodes (6): is_time_string(), parse_iso(), shift_dump_to_now(), shift_row_times(), shift_time_string(), move_to()

### Community 154 - "tests 154"
Cohesion: 0.22
Nodes (6): MemoryClient, _dump(), test_load_remaps_foreign_keys_disables_passwords_and_purges(), test_load_stops_when_a_member_already_exists(), test_memory_client_emulates_user_join_and_head_count(), test_memory_client_fills_only_real_columns_and_request_id()

### Community 156 - "netwatch 156"
Cohesion: 0.17
Nodes (11): app-layer, protocols, default-log-dir, default-rule-path, enabled, http, rule-files, stats (+3 more)

### Community 157 - "netwatch 157"
Cohesion: 0.17
Nodes (12): DNP3_PORTS, FILE_DATA_PORTS, FTP_PORTS, GENEVE_PORTS, HTTP_PORTS, MODBUS_PORTS, ORACLE_PORTS, SHELLCODE_PORTS (+4 more)

### Community 158 - "Next 번들 158"
Cohesion: 0.26
Nodes (12): f2(), f3(), f4(), f5(), f6(), f8(), f9(), fj() (+4 more)

### Community 159 - "tests 159"
Cohesion: 0.18
Nodes (3): _stub_status_queries(), test_expired_lock_cleanup_runs_concurrently_and_before_the_listing(), release()

### Community 160 - "Next 번들 160"
Cohesion: 0.49
Nodes (9): c(), d(), i(), l(), n(), o(), r(), s() (+1 more)

### Community 161 - "Next 번들 161"
Cohesion: 0.49
Nodes (9): c(), d(), i(), l(), n(), o(), r(), s() (+1 more)

### Community 162 - "Next 번들 162"
Cohesion: 0.56
Nodes (10): c(), d(), h(), i(), l(), n(), o(), r() (+2 more)

### Community 163 - "web 163"
Cohesion: 0.18
Nodes (7): out, problems, publicDir, SKIP, spaDir, walk(), web

### Community 164 - "tests 164"
Cohesion: 0.24
Nodes (3): FakeResponse, FakeSession, test_login_success_judgment()

### Community 165 - "db 165"
Cohesion: 0.20
Nodes (6): build_locks(), get_threat_stats(), api_stats(), _clear_status_cache_after_change(), test_status_and_stats_are_shared_between_tabs_within_the_cache_window(), test_build_locks_merges_ip_account_admin_with_permanent_first()

### Community 166 - "docker-compose.yml 166"
Cohesion: 0.20
Nodes (9): cap_add, image, networks, profiles, services, attacker-1, volumes, eve (+1 more)

### Community 167 - "Next 번들 167"
Cohesion: 0.22
Nodes (10): ab(), ak(), aS(), nA(), nB(), nf(), nk(), nO() (+2 more)

### Community 168 - "Next 번들 168"
Cohesion: 0.60
Nodes (9): c(), d(), i(), l(), n(), o(), r(), t() (+1 more)

### Community 169 - "tests 169"
Cohesion: 0.29
Nodes (5): _event(), test_build_report_classifies_fast_release_as_early(), test_build_report_does_not_classify_full_duration_release_as_early(), test_build_report_flags_high_ratio_for_review(), test_build_report_groups_by_event_type_separately()

### Community 170 - "db 170"
Cohesion: 0.22
Nodes (3): insert_playbook_run(), list_playbook_runs(), test_db_insert_and_export()

### Community 171 - "docker-compose.yml 171"
Cohesion: 0.22
Nodes (9): environment, environment, cap_add, environment, image, networks, profiles, TARGET_URL (+1 more)

### Community 172 - "docker-compose.yml 172"
Cohesion: 0.22
Nodes (9): container_name, depends_on, image, ports, restart, sysctls, volumes, gateway (+1 more)

### Community 173 - "netwatch 173"
Cohesion: 0.22
Nodes (3): CsrfTokenParser, extract_csrf_token(), fetch_login_csrf()

### Community 174 - "Next 번들 174"
Cohesion: 0.22
Nodes (9): fa(), fl(), fo(), fu(), hd(), ow(), oy(), tq() (+1 more)

### Community 176 - "tests 176"
Cohesion: 0.22
Nodes (4): test_trusted_proxy_disabled_uses_remote_addr(), test_trusted_proxy_empty_list_uses_xff(), test_trusted_proxy_remote_addr_in_list_uses_xff(), test_trusted_proxy_remote_addr_not_in_list_uses_remote_addr()

### Community 177 - "tests 177"
Cohesion: 0.39
Nodes (6): _adds(), _backend(), test_expired_ttl_is_not_re_added_while_app_is_down(), test_malformed_blocks_response_raises(), test_partially_elapsed_ttl_is_re_added_with_remaining_seconds(), test_permanent_block_is_always_re_added()

### Community 178 - "tests 178"
Cohesion: 0.25
Nodes (3): scapy_event(), test_main_rejects_invalid_stall_seconds(), test_to_event_maps_l4_detector_lines()

### Community 179 - "tests 179"
Cohesion: 0.29
Nodes (7): _is_idle(), _iso_minutes_ago(), test_is_idle_false_when_last_event_at_missing(), test_is_idle_false_within_merge_window_and_true_beyond_it(), test_is_idle_treats_naive_timestamp_as_utc(), test_record_incident_marks_stale_incident_idle_and_opens_new_one(), test_record_incident_still_merges_when_within_idle_window()

### Community 181 - "tests 181"
Cohesion: 0.25
Nodes (4): _compose_service_block(), test_compose_fw_agent_runs_by_default_without_db_keys(), test_compose_passes_stall_seconds_to_shipper(), test_compose_shipper_builds_from_own_folder()

### Community 182 - "tests 182"
Cohesion: 0.39
Nodes (5): _cleanup_call(), _function(), test_dry_run_and_access_controls_remain(), test_guide47_cleanup_body_is_preserved(), test_track_d_retention_periods_and_columns()

### Community 183 - "vercel.json 183"
Cohesion: 0.25
Nodes (7): includeFiles, main, functions, app.py, git, deploymentEnabled, headers

### Community 184 - "docker-compose.yml 184"
Cohesion: 0.29
Nodes (7): build, cap_add, depends_on, network_mode, restart, volumes, l4-detector

### Community 185 - "docker-compose.mailpit.yml 185"
Cohesion: 0.29
Nodes (6): container_name, image, ports, restart, services, mailpit

### Community 186 - "docker-compose.yml 186"
Cohesion: 0.29
Nodes (7): container_name, expose, image, networks, ports, restart, mailpit

### Community 187 - "netwatch 187"
Cohesion: 0.29
Nodes (7): af-packet, cluster-id, cluster-type, defrag, interface, tpacket-v3, use-mmap

### Community 188 - "netwatch 188"
Cohesion: 0.29
Nodes (7): enabled, enabled, logging, default-log-level, outputs, console, file

### Community 189 - "netwatch 189"
Cohesion: 0.29
Nodes (7): enabled, filename, filetype, enabled, outputs, eve-log, fast

### Community 190 - "netwatch 190"
Cohesion: 0.29
Nodes (7): types, extended, deltas, threads, totals, http, stats

### Community 193 - "tests 193"
Cohesion: 0.29
Nodes (3): test_tailer_reads_from_start_after_truncation(), test_tailer_reads_only_new_lines(), test_tailer_reads_recreated_file_from_start()

### Community 195 - "tests 195"
Cohesion: 0.33
Nodes (4): fake_server(), get(), __init__(), post()

### Community 199 - "netwatch 199"
Cohesion: 0.83
Nodes (3): find_edge_iface(), monitor_eve_size(), entrypoint.sh script

### Community 202 - "tests 202"
Cohesion: 0.50
Nodes (3): test_record_incident_falls_back_to_merge_on_unique_violation(), raising_insert(), test_record_incident_reraises_non_conflict_errors()

### Community 203 - "tests 203"
Cohesion: 0.50
Nodes (3): test_verify_admin_credentials_hashes_even_when_username_not_found(), spy_check_password_hash(), test_verify_user_credentials_hashes_even_when_username_not_found()

### Community 204 - "tests 204"
Cohesion: 0.50
Nodes (3): test_code_failures_look_identical_whether_or_not_the_account_exists(), test_temporary_and_permanent_account_locks_render_identically(), _without_csrf()

## Knowledge Gaps
- **33 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `L4Detector` connect `L4 탐지기(netwatch)` to `tests 55`?**
  _High betweenness centrality (0.017) - this node is a cross-community bridge._
- **Should `Next 번들 0` be split into smaller, more focused modules?**
  _Cohesion score 0.01454775458570525 - nodes in this community are weakly interconnected._
- **Why does `Query` connect `scripts 42` to `db 170`, `tests 154`?**
  _High betweenness centrality (0.009) - this node is a cross-community bridge._
- **Should `앱 통합 테스트` be split into smaller, more focused modules?**
  _Cohesion score 0.0343622597553873 - nodes in this community are weakly interconnected._
- **Should `DB 테스트(FakeQuery)` be split into smaller, more focused modules?**
  _Cohesion score 0.036281179138321996 - nodes in this community are weakly interconnected._
- **Should `Next 번들 3` be split into smaller, more focused modules?**
  _Cohesion score 0.054647599591419814 - nodes in this community are weakly interconnected._
- **Should `Next 번들 4` be split into smaller, more focused modules?**
  _Cohesion score 0.044409613375130615 - nodes in this community are weakly interconnected._