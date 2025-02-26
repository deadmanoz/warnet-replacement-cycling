.PHONY: down rc1 rc2 cycle1 cycle2

down:
	warnet down --force

rc1:
	warnet deploy networks/3_node_core
	warnet run scenarios/replacement_cycling_1.py --debug

rc2:
	warnet deploy networks/3_node_core_lnd
	warnet run scenarios/replacement_cycling_2.py --debug

cycle1: down rc1

cycle2: down rc2
