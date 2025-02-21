.PHONY: down rc1 rc2 rc3 cycle1 cycle2 cycle3

down:
	warnet down --force

rc1:
	warnet deploy networks/3_node_core
	warnet run scenarios/replacement_cycling_1.py --debug

rc2:
	warnet deploy networks/3_node_core
	warnet run scenarios/replacement_cycling_2.py --debug

rc3:
	warnet deploy networks/4_node_core
	warnet run scenarios/replacement_cycling_3.py --debug

cycle1: down rc1

cycle2: down rc2

cycle3: down rc3