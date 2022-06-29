package planner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gen0cide/laforge/builder"
	"github.com/gen0cide/laforge/ent"
	"github.com/gen0cide/laforge/ent/agenttask"
	"github.com/gen0cide/laforge/ent/buildcommit"
	"github.com/gen0cide/laforge/ent/plan"
	"github.com/gen0cide/laforge/ent/provisionedhost"
	"github.com/gen0cide/laforge/ent/provisionednetwork"
	"github.com/gen0cide/laforge/ent/provisioningstep"
	"github.com/gen0cide/laforge/ent/status"
	"github.com/gen0cide/laforge/logging"
	"github.com/gen0cide/laforge/server/utils"
	"github.com/sirupsen/logrus"
)

func StartBuild(client *ent.Client, laforgeConfig *utils.ServerConfig, logger *logging.Logger, currentUser *ent.AuthUser, serverTask *ent.ServerTask, taskStatus *ent.Status, entBuild *ent.Build) error {
	logger.Log.Debug("BUILDER | START BUILD")
	ctx := context.Background()
	defer ctx.Done()

	entPlans, err := entBuild.QueryBuildToPlan().Where(plan.HasPlanToStatusWith(status.StateEQ(status.StatePLANNING))).All(ctx)

	if err != nil {
		taskStatus, serverTask, err = utils.FailServerTask(ctx, client, rdb, taskStatus, serverTask)
		if err != nil {
			logger.Log.Errorf("Failed to Query Plan Nodes %v. Err: %v", entPlans, err)
			return err
		}
		logger.Log.Errorf("Failed to Query Plan Nodes %v. Err: %v", entPlans, err)
		return err
	}

	var wg sync.WaitGroup

	for _, entPlan := range entPlans {
		entStatus, err := entPlan.QueryPlanToStatus().Only(ctx)

		if err != nil {
			logger.Log.Errorf("Failed to Query Status %v. Err: %v", entPlan, err)
			return err
		}

		wg.Add(1)

		go func(wg *sync.WaitGroup, entStatus *ent.Status) {
			defer wg.Done()
			ctx := context.Background()
			defer ctx.Done()
			entStatus.Update().SetState(status.StateAWAITING).Save(ctx)
			rdb.Publish(ctx, "updatedStatus", entStatus.ID.String())
		}(&wg, entStatus)

		wg.Add(1)
		go func(wg *sync.WaitGroup, entPlan *ent.Plan) {
			defer wg.Done()
			ctx := context.Background()
			defer ctx.Done()
			switch entPlan.Type {
			case plan.TypeProvisionNetwork:
				entProNetwork, err := entPlan.QueryPlanToProvisionedNetwork().Only(ctx)
				if err != nil {
					logger.Log.Errorf("Failed to Query Provisioned Network. Err: %v", err)
					return
				}
				entStatus, err := entProNetwork.QueryProvisionedNetworkToStatus().Only(ctx)
				if err != nil {
					logger.Log.Errorf("Failed to Query Status %v. Err: %v", entPlan, err)
					return
				}
				entStatus.Update().SetState(status.StateAWAITING).Save(ctx)
				rdb.Publish(ctx, "updatedStatus", entStatus.ID.String())
			case plan.TypeProvisionHost:
				entProHost, err := entPlan.QueryPlanToProvisionedHost().Only(ctx)
				if err != nil {
					logger.Log.Errorf("Failed to Query Provisioned Host. Err: %v", err)
					return
				}
				entStatus, err := entProHost.QueryProvisionedHostToStatus().Only(ctx)
				if err != nil {
					logger.Log.Errorf("Failed to Query Status %v. Err: %v", entPlan, err)
					return
				}
				entStatus.Update().SetState(status.StateAWAITING).Save(ctx)
				rdb.Publish(ctx, "updatedStatus", entStatus.ID.String())
			case plan.TypeExecuteStep:
				entProvisioningStep, err := entPlan.QueryPlanToProvisioningStep().Only(ctx)
				if err != nil {
					logger.Log.Errorf("Failed to Query Provisioning Step. Err: %v", err)
					return
				}
				entStatus, err := entProvisioningStep.QueryProvisioningStepToStatus().Only(ctx)
				if err != nil {
					logger.Log.Errorf("Failed to Query Status %v. Err: %v", entPlan, err)
					return
				}
				entStatus.Update().SetState(status.StateAWAITING).Save(ctx)
				rdb.Publish(ctx, "updatedStatus", entStatus.ID.String())
			case plan.TypeStartTeam:
				entTeam, err := entPlan.QueryPlanToTeam().Only(ctx)
				if err != nil {
					logger.Log.Errorf("Failed to Query Provisioning Step. Err: %v", err)
					return
				}
				entStatus, err := entTeam.QueryTeamToStatus().Only(ctx)
				if err != nil {
					logger.Log.Errorf("Failed to Query Status %v. Err: %v", entPlan, err)
					return
				}
				entStatus.Update().SetState(status.StateAWAITING).Save(ctx)
				rdb.Publish(ctx, "updatedStatus", entStatus.ID.String())
			case plan.TypeStartBuild:
				entBuild, err := entPlan.QueryPlanToBuild().Only(ctx)
				if err != nil {
					logger.Log.Errorf("Failed to Query Provisioning Step. Err: %v", err)
					return
				}
				entStatus, err := entBuild.QueryBuildToStatus().Only(ctx)
				if err != nil {
					logger.Log.Errorf("Failed to Query Status %v. Err: %v", entPlan, err)
					return
				}
				entStatus.Update().SetState(status.StateAWAITING).Save(ctx)
				rdb.Publish(ctx, "updatedStatus", entStatus.ID.String())
			default:
				break
			}
		}(&wg, entPlan)
	}

	wg.Wait()

	rootPlans, err := entBuild.QueryBuildToPlan().Where(plan.TypeEQ(plan.TypeStartBuild)).All(ctx)
	if err != nil {
		taskStatus, serverTask, err = utils.FailServerTask(ctx, client, rdb, taskStatus, serverTask)
		if err != nil {
			logger.Log.Errorf("error failing execute build server task: %v", err)
			return err
		}
		logger.Log.Errorf("Failed to Query Start Plan Nodes. Err: %v", err)
		return err
	}
	environment, err := entBuild.QueryBuildToEnvironment().Only(ctx)
	if err != nil {
		taskStatus, serverTask, err = utils.FailServerTask(ctx, client, rdb, taskStatus, serverTask)
		if err != nil {
			logger.Log.Errorf("error failing execute build server task: %v", err)
			return err
		}
		logger.Log.Errorf("Failed to Query Environment. Err: %v", err)
		return err
	}

	genericBuilder, err := builder.BuilderFromEnvironment(laforgeConfig.Builders, environment, logger)
	if err != nil {
		logger.Log.Errorf("error generating builder: %v", err)
		taskStatus, serverTask, err = utils.FailServerTask(ctx, client, rdb, taskStatus, serverTask)
		if err != nil {
			logger.Log.Errorf("error failing execute build server task: %v", err)
			return err
		}
		return err
	}

	entRootCommit, err := entBuild.QueryBuildToLatestBuildCommit().Only(ctx)
	if err != nil {
		logger.Log.Errorf("error while querying lastest commit from build: %v", err)
		return err
	}

	err = entRootCommit.Update().SetState(buildcommit.StateINPROGRESS).Exec(ctx)
	if err != nil {
		logger.Log.Errorf("error while cancelling rebuild commit: %v", err)
		return err
	}
	rdb.Publish(ctx, "updatedBuildCommit", entRootCommit.ID.String())

	for _, entPlan := range rootPlans {
		wg.Add(1)
		go buildRoutine(client, laforgeConfig, logger, &genericBuilder, ctx, entPlan, &wg)
	}

	wg.Wait()

	taskStatus, serverTask, err = utils.CompleteServerTask(ctx, client, rdb, taskStatus, serverTask)
	if err != nil {
		logger.Log.Errorf("error completing execute build server task: %v", err)
		return err
	}

	err = entRootCommit.Update().SetState(buildcommit.StateAPPLIED).Exec(ctx)
	if err != nil {
		logger.Log.Errorf("error while cancelling rebuild commit: %v", err)
		return err
	}
	rdb.Publish(ctx, "updatedBuildCommit", entRootCommit.ID.String())

	return nil
}

func buildRoutine(client *ent.Client, laforgeConfig *utils.ServerConfig, logger *logging.Logger, builder *builder.Builder, ctx context.Context, entPlan *ent.Plan, wg *sync.WaitGroup) {
	logger.Log.WithFields(logrus.Fields{
		"plan": entPlan.ID,
	}).Debugf("BUILDER | BUILD ROUTINE START")
	defer wg.Done()

	entStatus, err := entPlan.QueryPlanToStatus().Only(ctx)

	if err != nil {
		logger.Log.Errorf("Failed to Query Status %v. Err: %v", entPlan, err)
		return
	}

	// If it isn't marked for planning, don't worry about traversing to it
	if entStatus.State != status.StateAWAITING {
		logger.Log.WithFields(logrus.Fields{
			"plan": entPlan.ID,
		}).Debugf("BUILDER | already awaiting. EXITING")
		return
	}

	// If it's already in progress, don't worry about traversing to it
	if entStatus.State == status.StatePARENTAWAITING || entStatus.State == status.StateINPROGRESS || entStatus.State == status.StateCOMPLETE {
		logger.Log.WithFields(logrus.Fields{
			"plan": entPlan.ID,
		}).Debugf("BUILDER | node already in progress. EXITING")
		return
	}

	prevNodes, err := entPlan.QueryPrevPlan().All(ctx)

	if err != nil {
		logger.Log.Errorf("Failed to Query Plan Start %v. Err: %v", prevNodes, err)
		return
	}

	logger.Log.WithFields(logrus.Fields{
		"plan": entPlan.ID,
	}).Debugf("BUILDER | waiting on parents")

	parentNodeFailed := false

	entStatus, err = entStatus.Update().SetState(status.StatePARENTAWAITING).Save(ctx)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"plan": entPlan.ID,
		}).Error("BUILDER | failed to set PARENTAWAITING status. EXITING")
		return
	}

	for _, prevNode := range prevNodes {
		for {

			if parentNodeFailed {
				break
			}

			prevCompletedStatus, err := prevNode.QueryPlanToStatus().Where(
				status.StateNEQ(
					status.StateCOMPLETE,
				),
			).Exist(ctx)

			if err != nil {
				logger.Log.Errorf("Failed to Query Status %v. Err: %v", prevNode, err)
				return
			}

			prevFailedStatus, err := prevNode.QueryPlanToStatus().Where(
				status.StateEQ(
					status.StateFAILED,
				),
			).Exist(ctx)

			if err != nil {
				logger.Log.Errorf("Failed to Query Status %v. Err: %v", prevNode, err)
				return
			}

			if !prevCompletedStatus {
				break
			}

			if prevFailedStatus {
				parentNodeFailed = true
				break
			}

			time.Sleep(time.Second)
		}
	}
	logger.Log.WithFields(logrus.Fields{
		"plan": entPlan.ID,
	}).Debugf("BUILDER | done waiting on parents")
	entStatus, err = entPlan.QueryPlanToStatus().Only(ctx)

	if err != nil {
		logger.Log.Errorf("Failed to Query Status %v. Err: %v", entPlan, err)
		return
	}

	entStatus.Update().SetState(status.StateINPROGRESS).Save(ctx)
	rdb.Publish(ctx, "updatedStatus", entStatus.ID.String())

	var planErr error = nil
	switch entPlan.Type {
	case plan.TypeProvisionNetwork:
		entProNetwork, err := entPlan.QueryPlanToProvisionedNetwork().Only(ctx)
		if err != nil {
			logger.Log.Errorf("Failed to Query Provisioned Network. Err: %v", err)
			return
		}
		if parentNodeFailed {
			networkStatus, err := entProNetwork.QueryProvisionedNetworkToStatus().Only(ctx)
			if err != nil {
				logger.Log.Errorf("Error while getting Provisioned Network status: %v", err)
				return
			}
			_, saveErr := networkStatus.Update().SetFailed(true).SetState(status.StateFAILED).Save(ctx)
			if saveErr != nil {
				logger.Log.Errorf("Error while setting Provisioned Network status to FAILED: %v", saveErr)
				return
			}
			rdb.Publish(ctx, "updatedStatus", networkStatus.ID.String())
			planErr = fmt.Errorf("parent node for Provionded Network has failed")
		} else {
			planErr = buildNetwork(client, logger, builder, ctx, entProNetwork)
		}
	case plan.TypeProvisionHost:
		entProHost, err := entPlan.QueryPlanToProvisionedHost().Only(ctx)
		if err != nil {
			logger.Log.Errorf("Failed to Query Provisioned Host. Err: %v", err)
			return
		}
		if parentNodeFailed {
			hostStatus, err := entProHost.QueryProvisionedHostToStatus().Only(ctx)
			if err != nil {
				logger.Log.Errorf("Error while getting Provisioned Network status: %v", err)
				return
			}
			_, saveErr := hostStatus.Update().SetFailed(true).SetState(status.StateFAILED).Save(ctx)
			if saveErr != nil {
				logger.Log.Errorf("Error while setting Provisioned Network status to FAILED: %v", saveErr)
				return
			}
			rdb.Publish(ctx, "updatedStatus", hostStatus.ID.String())
			planErr = fmt.Errorf("parent node for Provionded Host has failed")
		} else {
			planErr = buildHost(client, logger, builder, ctx, entProHost)
		}
	case plan.TypeExecuteStep:
		entProvisioningStep, err := entPlan.QueryPlanToProvisioningStep().Only(ctx)
		if err != nil {
			logger.Log.Errorf("Failed to Query Provisioning Step. Err: %v", err)
			return
		}
		if parentNodeFailed {
			stepStatus, err := entProvisioningStep.QueryProvisioningStepToStatus().Only(ctx)
			if err != nil {
				logger.Log.Errorf("Failed to Query Provisioning Step Status. Err: %v", err)
				return
			}
			_, err = stepStatus.Update().SetFailed(true).SetState(status.StateFAILED).Save(ctx)
			if err != nil {
				logger.Log.Errorf("error while trying to set ent.ProvisioningStep.Status.State to status.StateFAILED: %v", err)
				return
			}
			rdb.Publish(ctx, "updatedStatus", stepStatus.ID.String())
			planErr = fmt.Errorf("parent node for Provisioning Step has failed")
		} else {
			planErr = execStep(client, laforgeConfig, logger, ctx, entProvisioningStep)
		}
	case plan.TypeStartTeam:
		entTeam, err := entPlan.QueryPlanToTeam().Only(ctx)
		if err != nil {
			logger.Log.Errorf("Failed to Query Ent Tean. Err: %v", err)
			return
		}
		if parentNodeFailed {
			teamStatus, err := entTeam.QueryTeamToStatus().Only(ctx)
			if err != nil {
				logger.Log.Errorf("Failed to Query Provisioning Step Status. Err: %v", err)
				return
			}
			_, err = teamStatus.Update().SetFailed(true).SetState(status.StateFAILED).Save(ctx)
			if err != nil {
				logger.Log.Errorf("error while trying to set ent.ProvisioningStep.Status.State to status.StateFAILED: %v", err)
				return
			}
			rdb.Publish(ctx, "updatedStatus", teamStatus.ID.String())
			planErr = fmt.Errorf("parent node for Team has failed")
		} else {
			planErr = buildTeam(client, logger, builder, ctx, entTeam)
		}
	case plan.TypeStartBuild:
		entBuild, err := entPlan.QueryPlanToBuild().Only(ctx)
		if err != nil {
			logger.Log.Errorf("Failed to Query Provisioning Step. Err: %v", err)
			return
		}
		entStatus, err := entBuild.QueryBuildToStatus().Only(ctx)
		if err != nil {
			logger.Log.Errorf("Failed to Query Status %v. Err: %v", entPlan, err)
			return
		}
		entStatus.Update().SetState(status.StateCOMPLETE).Save(ctx)
		rdb.Publish(ctx, "updatedStatus", entStatus.ID.String())
	default:
		break
	}

	if planErr != nil {
		entStatus.Update().SetState(status.StateFAILED).SetFailed(true).Save(ctx)
		rdb.Publish(ctx, "updatedStatus", entStatus.ID.String())
		logger.Log.WithFields(logrus.Fields{
			"type":    entPlan.Type,
			"builder": (*builder).ID(),
		}).Errorf("error while executing plan: %v", planErr)
	} else {
		entStatus.Update().SetState(status.StateCOMPLETE).SetCompleted(true).Save(ctx)
		rdb.Publish(ctx, "updatedStatus", entStatus.ID.String())
	}

	logger.Log.WithFields(logrus.Fields{
		"plan": entPlan.ID,
	}).Debugf("BUILDER | plan done. SPAWNING CHILDREN")

	nextPlans, err := entPlan.QueryNextPlan().All(ctx)
	for _, nextPlan := range nextPlans {
		wg.Add(1)
		go buildRoutine(client, laforgeConfig, logger, builder, ctx, nextPlan, wg)
	}

}

func buildHost(client *ent.Client, logger *logging.Logger, builder *builder.Builder, ctx context.Context, entProHost *ent.ProvisionedHost) error {
	entProNet, err := entProHost.QueryProvisionedHostToProvisionedNetwork().First(ctx)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"entProHost": entProHost.ID,
		}).Error("error querying host and provisioned network from provisioned host")
		return err
	} else {
		entTeam, err := entProNet.QueryProvisionedNetworkToTeam().First(ctx)
		if err != nil {
			logger.Log.WithFields(logrus.Fields{
				"entProNet": entProNet.ID,
			}).Error("error querying team from provisioned network")
			return err
		} else {
			logger.Log.WithFields(logrus.Fields{
				"subnetIp":  entProHost.SubnetIP,
				"entProNet": entProNet.Name,
				"entTeam":   entTeam.TeamNumber,
			}).Debugf("BUILDER | BUILD ROUTINE START")
		}
	}
	logger.Log.Infof("deploying %s", entProHost.SubnetIP)
	hostStatus, err := entProHost.QueryProvisionedHostToStatus().Only(ctx)
	if err != nil {
		logger.Log.Errorf("Error while getting Provisioned Host status: %v", err)
		return err
	}
	entProNetwork, err := entProHost.QueryProvisionedHostToProvisionedNetwork().Only(ctx)
	if err != nil {
		logger.Log.Errorf("Error while checking if host step is failed: %v", err)
		return err
	}

	_, saveErr := hostStatus.Update().SetState(status.StateINPROGRESS).Save(ctx)
	if saveErr != nil {
		logger.Log.Errorf("Error while setting Provisioned Host status to INPROGRESS: %v", saveErr)
		return saveErr
	}
	rdb.Publish(ctx, "updatedStatus", hostStatus.ID.String())
	err = (*builder).DeployHost(ctx, entProHost)
	if err != nil {
		logger.Log.Errorf("Error while deploying host: %v", err)
		_, saveErr := hostStatus.Update().SetFailed(true).SetState(status.StateFAILED).Save(ctx)
		if saveErr != nil {
			logger.Log.Errorf("Error while setting Provisioned Host status to FAILED: %v", saveErr)
			return saveErr
		}
		rdb.Publish(ctx, "updatedStatus", hostStatus.ID.String())
		checkNetworkStatus(client, logger, ctx, entProNetwork)
		return err
	}
	logger.Log.Infof("deployed %s successfully", entProHost.SubnetIP)
	// _, saveErr = hostStatus.Update().SetCompleted(true).SetState(status.StateCOMPLETE).Save(ctx)
	// if saveErr != nil {
	// 	logger.Log.Errorf("Error while setting Provisioned Host status to COMPLETE: %v", saveErr)
	// 	return saveErr
	// }
	rdb.Publish(ctx, "updatedStatus", hostStatus.ID.String())
	return nil
}

func buildNetwork(client *ent.Client, logger *logging.Logger, builder *builder.Builder, ctx context.Context, entProNetwork *ent.ProvisionedNetwork) error {
	logger.Log.Infof("deploying %s", entProNetwork.Name)
	networkStatus, err := entProNetwork.QueryProvisionedNetworkToStatus().Only(ctx)
	if err != nil {
		logger.Log.Errorf("Error while getting Provisioned Network status: %v", err)
		return err
	}
	entTeam, err := entProNetwork.QueryProvisionedNetworkToTeam().Only(ctx)
	if err != nil {
		logger.Log.Errorf("Error while getting team: %v", err)
		return err
	}
	_, saveErr := networkStatus.Update().SetState(status.StateINPROGRESS).Save(ctx)
	if saveErr != nil {
		logger.Log.Errorf("Error while setting Provisioned Network status to INPROGRESS: %v", saveErr)
		return saveErr
	}
	rdb.Publish(ctx, "updatedStatus", networkStatus.ID.String())
	err = (*builder).DeployNetwork(ctx, entProNetwork)
	if err != nil {
		logger.Log.Errorf("Error while deploying network: %v", err)
		_, saveErr := networkStatus.Update().SetFailed(true).SetState(status.StateFAILED).Save(ctx)
		if saveErr != nil {
			logger.Log.Errorf("Error while setting Provisioned Network status to FAILED: %v", saveErr)
			return saveErr
		}
		rdb.Publish(ctx, "updatedStatus", networkStatus.ID.String())
		checkTeamStatus(client, logger, ctx, entTeam)
		return err
	}
	logger.Log.Infof("deployed %s successfully", entProNetwork.Name)

	// _, saveErr = networkStatus.Update().SetCompleted(true).SetState(status.StateCOMPLETE).Save(ctx)
	// if saveErr != nil {
	// 	logger.Log.Errorf("Error while setting Provisioned Network status to COMPLETE: %v", saveErr)
	// 	return saveErr
	// }
	// rdb.Publish(ctx, "updatedStatus", networkStatus.ID.String())
	return nil
}

func buildTeam(client *ent.Client, logger *logging.Logger, builder *builder.Builder, ctx context.Context, entTeam *ent.Team) error {
	logger.Log.Infof("deploying Team: %d", entTeam.TeamNumber)

	teamStatus, err := entTeam.QueryTeamToStatus().Only(ctx)
	if err != nil {
		logger.Log.Errorf("Error while getting Team status: %v", err)
		return err
	}
	_, saveErr := teamStatus.Update().SetState(status.StateINPROGRESS).Save(ctx)
	if saveErr != nil {
		logger.Log.Errorf("Error while setting Team status to INPROGRESS: %v", saveErr)
		return saveErr
	}
	rdb.Publish(ctx, "updatedStatus", teamStatus.ID.String())
	err = (*builder).DeployTeam(ctx, entTeam)
	if err != nil {
		logger.Log.Errorf("Error while deploying network: %v", err)
		_, saveErr := teamStatus.Update().SetFailed(true).SetState(status.StateFAILED).Save(ctx)
		if saveErr != nil {
			logger.Log.Errorf("Error while setting Provisioned Network status to FAILED: %v", saveErr)
			return saveErr
		}
		rdb.Publish(ctx, "updatedStatus", teamStatus.ID.String())
		checkTeamStatus(client, logger, ctx, entTeam)
		return err
	}
	logger.Log.Infof("deployed %d successfully", entTeam.TeamNumber)
	return nil
}

func checkTeamStatus(client *ent.Client, logger *logging.Logger, ctx context.Context, entTeam *ent.Team) error {
	stepAwaitingInProgress, err := entTeam.
		QueryTeamToProvisionedNetwork().
		Where(
			provisionednetwork.
				HasProvisionedNetworkToStatusWith(
					status.Or(
						status.StateEQ(status.StateAWAITING),
						status.StateEQ(status.StateINPROGRESS),
					),
				),
		).Exist(ctx)
	if err != nil {
		logger.Log.Errorf("Error while checking if host step is in progress: %v", err)
		return err
	}
	if stepAwaitingInProgress {
		logger.Log.Debug("team %s is in progress", entTeam.ID)
		return nil
	}

	teamStatus, err := entTeam.QueryTeamToStatus().Only(ctx)
	if teamStatus.State != status.StateINPROGRESS {
		return nil
	}

	hostFailed, err := entTeam.
		QueryTeamToProvisionedNetwork().
		Where(
			provisionednetwork.
				HasProvisionedNetworkToStatusWith(
					status.Or(
						status.StateEQ(status.StateFAILED),
						status.StateEQ(status.StateTAINTED),
					),
				),
		).Exist(ctx)
	if err != nil {
		logger.Log.Errorf("Error while checking if host step is failed: %v", err)
		return err
	}
	if hostFailed {
		_, saveErr := teamStatus.Update().SetCompleted(false).SetFailed(true).SetState(status.StateTAINTED).Save(ctx)
		if saveErr != nil {
			logger.Log.Errorf("Error while setting Provisioned Network status to Tainted: %v", saveErr)
			return saveErr
		}
		rdb.Publish(ctx, "updatedStatus", teamStatus.ID.String())
		logger.Log.Debug("host %s is failed", teamStatus.ID)
		return nil
	}

	stepNotCompleted, err := entTeam.
		QueryTeamToProvisionedNetwork().
		Where(
			provisionednetwork.
				HasProvisionedNetworkToStatusWith(
					status.StateNEQ(status.StateCOMPLETE),
				),
		).Exist(ctx)
	if err != nil {
		logger.Log.Errorf("Error while checking if host step is failed: %v", err)
		return err
	}
	if !stepNotCompleted {
		_, saveErr := teamStatus.Update().SetCompleted(true).SetFailed(false).SetState(status.StateCOMPLETE).Save(ctx)
		if saveErr != nil {
			logger.Log.Errorf("Error while setting Provisioned Network status to Completed: %v", saveErr)
			return saveErr
		}
		rdb.Publish(ctx, "updatedStatus", teamStatus.ID.String())
		logger.Log.Debug("host %s is failed", teamStatus.ID)
		return nil
	}
	return nil
}

func checkNetworkStatus(client *ent.Client, logger *logging.Logger, ctx context.Context, entProNetwork *ent.ProvisionedNetwork) error {
	stepAwaitingInProgress, err := entProNetwork.
		QueryProvisionedNetworkToProvisionedHost().
		Where(
			provisionedhost.
				HasProvisionedHostToStatusWith(
					status.Or(
						status.StateEQ(status.StateAWAITING),
						status.StateEQ(status.StateINPROGRESS),
					),
				),
		).Exist(ctx)
	if err != nil {
		logger.Log.Errorf("Error while checking if host step is in progress: %v", err)
		return err
	}
	if stepAwaitingInProgress {
		logger.Log.Debug("network %s is in progress", entProNetwork.ID)
		return nil
	}

	networkStatus, err := entProNetwork.QueryProvisionedNetworkToStatus().Only(ctx)
	if networkStatus.State != status.StateINPROGRESS {
		return nil
	}
	entTeam, err := entProNetwork.QueryProvisionedNetworkToTeam().Only(ctx)
	if err != nil {
		logger.Log.Errorf("Error while getting team: %v", err)
		return err
	}

	hostFailed, err := entProNetwork.
		QueryProvisionedNetworkToProvisionedHost().
		Where(
			provisionedhost.
				HasProvisionedHostToStatusWith(
					status.Or(
						status.StateEQ(status.StateFAILED),
						status.StateEQ(status.StateTAINTED),
					),
				),
		).Exist(ctx)
	if err != nil {
		logger.Log.Errorf("Error while checking if host step is failed: %v", err)
		return err
	}
	if hostFailed {
		_, saveErr := networkStatus.Update().SetCompleted(false).SetFailed(true).SetState(status.StateTAINTED).Save(ctx)
		if saveErr != nil {
			logger.Log.Errorf("Error while setting Provisioned Network status to Tainted: %v", saveErr)
			return saveErr
		}
		rdb.Publish(ctx, "updatedStatus", networkStatus.ID.String())
		logger.Log.Debug("host %s is failed", networkStatus.ID)
		checkTeamStatus(client, logger, ctx, entTeam)
		return nil
	}

	stepNotCompleted, err := entProNetwork.
		QueryProvisionedNetworkToProvisionedHost().
		Where(
			provisionedhost.
				HasProvisionedHostToStatusWith(
					status.StateNEQ(status.StateCOMPLETE),
				),
		).Exist(ctx)
	if err != nil {
		logger.Log.Errorf("Error while checking if host step is failed: %v", err)
		return err
	}
	if !stepNotCompleted {
		_, saveErr := networkStatus.Update().SetCompleted(true).SetFailed(false).SetState(status.StateCOMPLETE).Save(ctx)
		if saveErr != nil {
			logger.Log.Errorf("Error while setting Provisioned Network status to Completed: %v", saveErr)
			return saveErr
		}
		rdb.Publish(ctx, "updatedStatus", networkStatus.ID.String())
		logger.Log.Debug("host %s is Completed", networkStatus.ID)
		checkTeamStatus(client, logger, ctx, entTeam)
		return nil
	}
	return nil
}

func checkHostStatus(client *ent.Client, logger *logging.Logger, ctx context.Context, entProHost *ent.ProvisionedHost) error {
	hostStatus, err := entProHost.QueryProvisionedHostToStatus().Only(ctx)
	if hostStatus.State != status.StateINPROGRESS {
		return nil
	}
	entProNetwork, err := entProHost.QueryProvisionedHostToProvisionedNetwork().Only(ctx)
	if err != nil {
		logger.Log.Errorf("Error while checking if host step is failed: %v", err)
		return err
	}

	stepFailed, err := entProHost.
		QueryProvisionedHostToProvisioningStep().
		Where(
			provisioningstep.
				HasProvisioningStepToStatusWith(
					status.StateEQ(status.StateFAILED),
				),
		).Exist(ctx)
	if err != nil {
		logger.Log.Errorf("Error while checking if host step is failed: %v", err)
		return err
	}
	if stepFailed {
		_, saveErr := hostStatus.Update().SetCompleted(false).SetFailed(true).SetState(status.StateTAINTED).Save(ctx)
		if saveErr != nil {
			logger.Log.Errorf("Error while setting Provisioned Host status to Tainted: %v", saveErr)
			return saveErr
		}
		rdb.Publish(ctx, "updatedStatus", hostStatus.ID.String())
		logger.Log.Debug("host %s is failed", entProHost.ID)
		checkNetworkStatus(client, logger, ctx, entProNetwork)
		return nil
	}

	stepNotCompleted, err := entProHost.
		QueryProvisionedHostToProvisioningStep().
		Where(
			provisioningstep.
				HasProvisioningStepToStatusWith(
					status.StateNEQ(status.StateCOMPLETE),
				),
		).Exist(ctx)
	if err != nil {
		logger.Log.Errorf("Error while checking if host step is failed: %v", err)
		return err
	}
	if !stepNotCompleted {
		_, saveErr := hostStatus.Update().SetCompleted(true).SetFailed(false).SetState(status.StateCOMPLETE).Save(ctx)
		if saveErr != nil {
			logger.Log.Errorf("Error while setting Provisioned Host status to Completed: %v", saveErr)
			return saveErr
		}
		rdb.Publish(ctx, "updatedStatus", hostStatus.ID.String())
		logger.Log.Debug("host %s is completed", entProHost.ID)
		checkNetworkStatus(client, logger, ctx, entProNetwork)
		return nil
	}
	return nil
}

func execStep(client *ent.Client, laforgeConfig *utils.ServerConfig, logger *logging.Logger, ctx context.Context, entStep *ent.ProvisioningStep) error {
	stepStatus, err := entStep.QueryProvisioningStepToStatus().Only(ctx)
	if err != nil {
		logger.Log.Errorf("Failed to Query Provisioning Step Status. Err: %v", err)
		return err
	}
	_, err = stepStatus.Update().SetState(status.StateINPROGRESS).Save(ctx)
	if err != nil {
		logger.Log.Errorf("error while trying to set ent.ProvisioningStep.Status.State to status.StateCOMPLETED: %v", err)
		return err
	}
	rdb.Publish(ctx, "updatedStatus", stepStatus.ID.String())

	entProvisionedHost, err := entStep.QueryProvisioningStepToProvisionedHost().Only(ctx)
	if err != nil {
		logger.Log.Errorf("failed querying Provisioned Host for Provioning Step: %v", err)
		return err
	}

	taskCount, err := entProvisionedHost.QueryProvisionedHostToAgentTask().Count(ctx)
	if err != nil {
		logger.Log.Errorf("failed querying Number of Tasks: %v", err)
		return err
	}

	switch entStep.Type {
	case provisioningstep.TypeScript:
		entScript, err := entStep.QueryProvisioningStepToScript().Only(ctx)
		if err != nil {
			logger.Log.Errorf("failed querying Script for Provioning Step: %v", err)
			return err
		}
		if _, ok := entScript.Vars["build_render"]; ok {
			_, err := renderScript(ctx, client, logger, entStep)
			if err != nil {
				logger.Log.Errorf("failed rerendering Script: %v", err)
				return err
			}
			logger.Log.Debug("sucessful rerendering for Script: %v", err)
		}
		entGinMiddleware, err := entStep.QueryProvisioningStepToGinFileMiddleware().Only(ctx)
		if err != nil {
			logger.Log.Errorf("failed querying Gin File Middleware for Script: %v", err)
			return err
		}
		_, err = client.AgentTask.Create().
			SetCommand(agenttask.CommandDOWNLOAD).
			SetArgs(entScript.Source + "💔" + laforgeConfig.Agent.ApiDownloadUrl + entGinMiddleware.URLID).
			SetNumber(taskCount).
			SetState(agenttask.StateAWAITING).
			SetAgentTaskToProvisionedHost(entProvisionedHost).
			SetAgentTaskToProvisioningStep(entStep).
			Save(ctx)
		if err != nil {
			logger.Log.Errorf("failed Creating Agent Task for Script Download: %v", err)
			return err
		}
		// TODO: Add the Ability to change permissions of a file into the agent
		_, err = client.AgentTask.Create().
			SetCommand(agenttask.CommandEXECUTE).
			SetArgs(entScript.Source + "💔" + strings.Join(entScript.Args, " ")).
			SetNumber(taskCount + 1).
			SetState(agenttask.StateAWAITING).
			SetAgentTaskToProvisionedHost(entProvisionedHost).
			SetAgentTaskToProvisioningStep(entStep).
			Save(ctx)
		if err != nil {
			logger.Log.Errorf("failed Creating Agent Task for Script Execute: %v", err)
			return err
		}
		_, err = client.AgentTask.Create().
			SetCommand(agenttask.CommandDELETE).
			SetArgs(entScript.Source).
			SetNumber(taskCount + 2).
			SetState(agenttask.StateAWAITING).
			SetAgentTaskToProvisionedHost(entProvisionedHost).
			SetAgentTaskToProvisioningStep(entStep).
			Save(ctx)
		if err != nil {
			logger.Log.Errorf("failed Creating Agent Task for Script Delete: %v", err)
			return err
		}
	case provisioningstep.TypeCommand:
		entCommand, err := entStep.QueryProvisioningStepToCommand().Only(ctx)
		if err != nil {
			logger.Log.Errorf("failed querying Command for Provioning Step: %v", err)
			return err
		}
		// Check if reboot command
		if entCommand.Program == "REBOOT" {
			_, err = client.AgentTask.Create().
				SetCommand(agenttask.CommandREBOOT).
				SetArgs("").
				SetNumber(taskCount).
				SetState(agenttask.StateAWAITING).
				SetAgentTaskToProvisionedHost(entProvisionedHost).
				SetAgentTaskToProvisioningStep(entStep).
				Save(ctx)
			if err != nil {
				logger.Log.Errorf("failed Creating Agent Task for Reboot Command: %v", err)
				return err
			}
		} else {
			_, err = client.AgentTask.Create().
				SetCommand(agenttask.CommandEXECUTE).
				SetArgs(entCommand.Program + "💔" + strings.Join(entCommand.Args, " ")).
				SetNumber(taskCount).
				SetState(agenttask.StateAWAITING).
				SetAgentTaskToProvisionedHost(entProvisionedHost).
				SetAgentTaskToProvisioningStep(entStep).
				Save(ctx)
			if err != nil {
				logger.Log.Errorf("failed Creating Agent Task for Command: %v", err)
				return err
			}
		}
	case provisioningstep.TypeFileDelete:
		entFileDelete, err := entStep.QueryProvisioningStepToFileDelete().Only(ctx)
		if err != nil {
			logger.Log.Errorf("failed querying File Delete for Provioning Step: %v", err)
			return err
		}
		_, err = client.AgentTask.Create().
			SetCommand(agenttask.CommandDELETE).
			SetArgs(entFileDelete.Path).
			SetNumber(taskCount).
			SetState(agenttask.StateAWAITING).
			SetAgentTaskToProvisionedHost(entProvisionedHost).
			SetAgentTaskToProvisioningStep(entStep).
			Save(ctx)
		if err != nil {
			logger.Log.Errorf("failed Creating Agent Task for File Delete: %v", err)
			return err
		}
	case provisioningstep.TypeFileDownload:
		entFileDownload, err := entStep.QueryProvisioningStepToFileDownload().Only(ctx)
		if err != nil {
			logger.Log.Errorf("failed querying File Download for Provioning Step: %v", err)
			return err
		}
		entGinMiddleware, err := entStep.QueryProvisioningStepToGinFileMiddleware().Only(ctx)
		if err != nil {
			logger.Log.Errorf("failed querying Gin File Middleware for File Download: %v", err)
			return err
		}
		if entFileDownload.SourceType == "remote" {
			_, err = client.AgentTask.Create().
				SetCommand(agenttask.CommandDOWNLOAD).
				SetArgs(entFileDownload.Destination + "💔" + entFileDownload.Source).
				SetNumber(taskCount).
				SetState(agenttask.StateAWAITING).
				SetAgentTaskToProvisionedHost(entProvisionedHost).
				SetAgentTaskToProvisioningStep(entStep).
				Save(ctx)
		} else {
			_, err = client.AgentTask.Create().
				SetCommand(agenttask.CommandDOWNLOAD).
				SetArgs(entFileDownload.Destination + "💔" + laforgeConfig.Agent.ApiDownloadUrl + entGinMiddleware.URLID).
				SetNumber(taskCount).
				SetState(agenttask.StateAWAITING).
				SetAgentTaskToProvisionedHost(entProvisionedHost).
				SetAgentTaskToProvisioningStep(entStep).
				Save(ctx)
		}
		if err != nil {
			logger.Log.Errorf("failed Creating Agent Task for File Download: %v", err)
			return err
		}
	case provisioningstep.TypeFileExtract:
		entFileExtract, err := entStep.QueryProvisioningStepToFileExtract().Only(ctx)
		if err != nil {
			logger.Log.Errorf("failed querying File Extract for Provioning Step: %v", err)
			return err
		}
		_, err = client.AgentTask.Create().
			SetCommand(agenttask.CommandEXTRACT).
			SetArgs(entFileExtract.Source + "💔" + entFileExtract.Destination).
			SetNumber(taskCount).
			SetState(agenttask.StateAWAITING).
			SetAgentTaskToProvisionedHost(entProvisionedHost).
			SetAgentTaskToProvisioningStep(entStep).
			Save(ctx)
		if err != nil {
			logger.Log.Errorf("failed Creating Agent Task for File Extract: %v", err)
			return err
		}
	case provisioningstep.TypeDNSRecord:
		break
	case provisioningstep.TypeAnsible:
		entAnsible, err := entStep.QueryProvisioningStepToAnsible().Only(ctx)
		if err != nil {
			logger.Log.Errorf("failed querying Ansible for Provioning Step: %v", err)
			return err
		}
		entGinMiddleware, err := entStep.QueryProvisioningStepToGinFileMiddleware().Only(ctx)
		if err != nil {
			logger.Log.Errorf("failed querying Gin File Middleware for Script: %v", err)
			return err
		}
		_, err = client.AgentTask.Create().
			SetCommand(agenttask.CommandDOWNLOAD).
			SetArgs("/tmp/" + entAnsible.Name + ".zip" + "💔" + laforgeConfig.Agent.ApiDownloadUrl + entGinMiddleware.URLID).
			SetNumber(taskCount).
			SetState(agenttask.StateAWAITING).
			SetAgentTaskToProvisionedHost(entProvisionedHost).
			SetAgentTaskToProvisioningStep(entStep).
			Save(ctx)
		if err != nil {
			logger.Log.Errorf("failed Creating Agent Task for Script Download: %v", err)
			return err
		}
		_, err = client.AgentTask.Create().
			SetCommand(agenttask.CommandEXTRACT).
			SetArgs("/tmp/" + entAnsible.Name + ".zip" + "💔" + "/tmp").
			SetNumber(taskCount + 1).
			SetState(agenttask.StateAWAITING).
			SetAgentTaskToProvisionedHost(entProvisionedHost).
			SetAgentTaskToProvisioningStep(entStep).
			Save(ctx)
		if err != nil {
			logger.Log.Errorf("failed Creating Agent Task for Script Download: %v", err)
			return err
		}
		_, err = client.AgentTask.Create().
			SetCommand(agenttask.CommandANSIBLE).
			SetArgs("/tmp/" + entAnsible.Name + "/" + entAnsible.PlaybookName + "💔" + string(entAnsible.Method) + "💔" + entAnsible.Inventory).
			SetNumber(taskCount + 2).
			SetState(agenttask.StateAWAITING).
			SetAgentTaskToProvisionedHost(entProvisionedHost).
			SetAgentTaskToProvisioningStep(entStep).
			Save(ctx)
		if err != nil {
			logger.Log.Errorf("failed Creating Agent Task for Script Execute: %v", err)
			return err
		}
		_, err = client.AgentTask.Create().
			SetCommand(agenttask.CommandDELETE).
			SetArgs("/tmp/" + entAnsible.Name).
			SetNumber(taskCount + 3).
			SetState(agenttask.StateAWAITING).
			SetAgentTaskToProvisionedHost(entProvisionedHost).
			SetAgentTaskToProvisioningStep(entStep).
			Save(ctx)
		if err != nil {
			logger.Log.Errorf("failed Creating Agent Task for Script Delete: %v", err)
			return err
		}
		_, err = client.AgentTask.Create().
			SetCommand(agenttask.CommandDELETE).
			SetArgs("/tmp/" + entAnsible.Name + ".zip").
			SetNumber(taskCount + 4).
			SetState(agenttask.StateAWAITING).
			SetAgentTaskToProvisionedHost(entProvisionedHost).
			SetAgentTaskToProvisioningStep(entStep).
			Save(ctx)
		if err != nil {
			logger.Log.Errorf("failed Creating Agent Task for Script Delete: %v", err)
			return err
		}
	default:
		break
	}

	for {
		taskFailed, err := entStep.QueryProvisioningStepToAgentTask().Where(
			agenttask.StateEQ(
				agenttask.StateFAILED,
			),
		).Exist(ctx)

		if err != nil {
			logger.Log.Errorf("Failed to Query Agent Task State. Err: %v", err)
			return err
		}

		if taskFailed {
			_, err = stepStatus.Update().SetFailed(true).SetState(status.StateFAILED).Save(ctx)
			if err != nil {
				logger.Log.Errorf("error while trying to set ent.ProvisioningStep.Status.State to status.StateFAILED: %v", err)
				return err
			}
			checkHostStatus(client, logger, ctx, entProvisionedHost)
			rdb.Publish(ctx, "updatedStatus", stepStatus.ID.String())
			return fmt.Errorf("one or more agent tasks failed")
		}

		taskRunning, err := entStep.QueryProvisioningStepToAgentTask().Where(
			agenttask.StateNEQ(
				agenttask.StateCOMPLETE,
			),
		).Exist(ctx)

		if err != nil {
			logger.Log.Errorf("Failed to Query Agent Task State. Err: %v", err)
			return err
		}

		if !taskRunning {
			break
		}

		time.Sleep(time.Second)
	}
	_, err = stepStatus.Update().SetCompleted(true).SetState(status.StateCOMPLETE).Save(ctx)

	if err != nil {
		logger.Log.Errorf("error while trying to set ent.ProvisioningStep.Status.State to status.StateCOMPLETED: %v", err)
		return err
	}
	checkHostStatus(client, logger, ctx, entProvisionedHost)
	rdb.Publish(ctx, "updatedStatus", stepStatus.ID.String())

	return nil
}
