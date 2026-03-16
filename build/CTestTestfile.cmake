# CMake generated Testfile for 
# Source directory: /home/visage/Рабочий стол/WG_radius
# Build directory: /home/visage/Рабочий стол/WG_radius/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[wg_radius_domain_tests]=] "/home/visage/Рабочий стол/WG_radius/build/wg_radius_domain_tests")
set_tests_properties([=[wg_radius_domain_tests]=] PROPERTIES  _BACKTRACE_TRIPLES "/home/visage/Рабочий стол/WG_radius/CMakeLists.txt;70;add_test;/home/visage/Рабочий стол/WG_radius/CMakeLists.txt;0;")
add_test([=[wg_radius_phase1_integration]=] "/home/visage/Рабочий стол/WG_radius/tests/integration/phase1_real_wg_smoke.sh" "/home/visage/Рабочий стол/WG_radius/build/wg_native_smoke" "/home/visage/Рабочий стол/WG_radius/build/wg_radiusd" "/home/visage/Рабочий стол/WG_radius")
set_tests_properties([=[wg_radius_phase1_integration]=] PROPERTIES  LABELS "integration;wireguard;phase1" SKIP_RETURN_CODE "77" _BACKTRACE_TRIPLES "/home/visage/Рабочий стол/WG_radius/CMakeLists.txt;95;add_test;/home/visage/Рабочий стол/WG_radius/CMakeLists.txt;0;")
