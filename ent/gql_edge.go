// Code generated by ent, DO NOT EDIT.

package ent

import "context"

func (ap *AdhocPlan) PrevAdhocPlan(ctx context.Context) ([]*AdhocPlan, error) {
	result, err := ap.Edges.PrevAdhocPlanOrErr()
	if IsNotLoaded(err) {
		result, err = ap.QueryPrevAdhocPlan().All(ctx)
	}
	return result, err
}

func (ap *AdhocPlan) NextAdhocPlans(ctx context.Context) ([]*AdhocPlan, error) {
	result, err := ap.Edges.NextAdhocPlansOrErr()
	if IsNotLoaded(err) {
		result, err = ap.QueryNextAdhocPlans().All(ctx)
	}
	return result, err
}

func (ap *AdhocPlan) Build(ctx context.Context) (*Build, error) {
	result, err := ap.Edges.BuildOrErr()
	if IsNotLoaded(err) {
		result, err = ap.QueryBuild().Only(ctx)
	}
	return result, err
}

func (ap *AdhocPlan) Status(ctx context.Context) (*Status, error) {
	result, err := ap.Edges.StatusOrErr()
	if IsNotLoaded(err) {
		result, err = ap.QueryStatus().Only(ctx)
	}
	return result, err
}

func (ap *AdhocPlan) AgentTask(ctx context.Context) (*AgentTask, error) {
	result, err := ap.Edges.AgentTaskOrErr()
	if IsNotLoaded(err) {
		result, err = ap.QueryAgentTask().Only(ctx)
	}
	return result, err
}

func (as *AgentStatus) ProvisionedHost(ctx context.Context) (*ProvisionedHost, error) {
	result, err := as.Edges.ProvisionedHostOrErr()
	if IsNotLoaded(err) {
		result, err = as.QueryProvisionedHost().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (as *AgentStatus) ProvisionedNetwork(ctx context.Context) (*ProvisionedNetwork, error) {
	result, err := as.Edges.ProvisionedNetworkOrErr()
	if IsNotLoaded(err) {
		result, err = as.QueryProvisionedNetwork().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (as *AgentStatus) Build(ctx context.Context) (*Build, error) {
	result, err := as.Edges.BuildOrErr()
	if IsNotLoaded(err) {
		result, err = as.QueryBuild().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (at *AgentTask) ProvisioningStep(ctx context.Context) (*ProvisioningStep, error) {
	result, err := at.Edges.ProvisioningStepOrErr()
	if IsNotLoaded(err) {
		result, err = at.QueryProvisioningStep().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (at *AgentTask) ProvisioningScheduledStep(ctx context.Context) (*ProvisioningScheduledStep, error) {
	result, err := at.Edges.ProvisioningScheduledStepOrErr()
	if IsNotLoaded(err) {
		result, err = at.QueryProvisioningScheduledStep().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (at *AgentTask) ProvisionedHost(ctx context.Context) (*ProvisionedHost, error) {
	result, err := at.Edges.ProvisionedHostOrErr()
	if IsNotLoaded(err) {
		result, err = at.QueryProvisionedHost().Only(ctx)
	}
	return result, err
}

func (at *AgentTask) AdhocPlans(ctx context.Context) ([]*AdhocPlan, error) {
	result, err := at.Edges.AdhocPlansOrErr()
	if IsNotLoaded(err) {
		result, err = at.QueryAdhocPlans().All(ctx)
	}
	return result, err
}

func (a *Ansible) Users(ctx context.Context) ([]*User, error) {
	result, err := a.Edges.UsersOrErr()
	if IsNotLoaded(err) {
		result, err = a.QueryUsers().All(ctx)
	}
	return result, err
}

func (a *Ansible) Environment(ctx context.Context) (*Environment, error) {
	result, err := a.Edges.EnvironmentOrErr()
	if IsNotLoaded(err) {
		result, err = a.QueryEnvironment().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (au *AuthUser) Tokens(ctx context.Context) ([]*Token, error) {
	result, err := au.Edges.TokensOrErr()
	if IsNotLoaded(err) {
		result, err = au.QueryTokens().All(ctx)
	}
	return result, err
}

func (au *AuthUser) ServerTasks(ctx context.Context) ([]*ServerTask, error) {
	result, err := au.Edges.ServerTasksOrErr()
	if IsNotLoaded(err) {
		result, err = au.QueryServerTasks().All(ctx)
	}
	return result, err
}

func (b *Build) Status(ctx context.Context) (*Status, error) {
	result, err := b.Edges.StatusOrErr()
	if IsNotLoaded(err) {
		result, err = b.QueryStatus().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (b *Build) Environment(ctx context.Context) (*Environment, error) {
	result, err := b.Edges.EnvironmentOrErr()
	if IsNotLoaded(err) {
		result, err = b.QueryEnvironment().Only(ctx)
	}
	return result, err
}

func (b *Build) Competition(ctx context.Context) (*Competition, error) {
	result, err := b.Edges.CompetitionOrErr()
	if IsNotLoaded(err) {
		result, err = b.QueryCompetition().Only(ctx)
	}
	return result, err
}

func (b *Build) LatestBuildCommit(ctx context.Context) (*BuildCommit, error) {
	result, err := b.Edges.LatestBuildCommitOrErr()
	if IsNotLoaded(err) {
		result, err = b.QueryLatestBuildCommit().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (b *Build) RepoCommits(ctx context.Context) (*RepoCommit, error) {
	result, err := b.Edges.RepoCommitsOrErr()
	if IsNotLoaded(err) {
		result, err = b.QueryRepoCommits().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (b *Build) ProvisionedNetworks(ctx context.Context) ([]*ProvisionedNetwork, error) {
	result, err := b.Edges.ProvisionedNetworksOrErr()
	if IsNotLoaded(err) {
		result, err = b.QueryProvisionedNetworks().All(ctx)
	}
	return result, err
}

func (b *Build) Teams(ctx context.Context) ([]*Team, error) {
	result, err := b.Edges.TeamsOrErr()
	if IsNotLoaded(err) {
		result, err = b.QueryTeams().All(ctx)
	}
	return result, err
}

func (b *Build) Plans(ctx context.Context) ([]*Plan, error) {
	result, err := b.Edges.PlansOrErr()
	if IsNotLoaded(err) {
		result, err = b.QueryPlans().All(ctx)
	}
	return result, err
}

func (b *Build) BuildCommits(ctx context.Context) ([]*BuildCommit, error) {
	result, err := b.Edges.BuildCommitsOrErr()
	if IsNotLoaded(err) {
		result, err = b.QueryBuildCommits().All(ctx)
	}
	return result, err
}

func (b *Build) AdhocPlans(ctx context.Context) ([]*AdhocPlan, error) {
	result, err := b.Edges.AdhocPlansOrErr()
	if IsNotLoaded(err) {
		result, err = b.QueryAdhocPlans().All(ctx)
	}
	return result, err
}

func (b *Build) AgentStatuses(ctx context.Context) ([]*AgentStatus, error) {
	result, err := b.Edges.AgentStatusesOrErr()
	if IsNotLoaded(err) {
		result, err = b.QueryAgentStatuses().All(ctx)
	}
	return result, err
}

func (b *Build) ServerTasks(ctx context.Context) ([]*ServerTask, error) {
	result, err := b.Edges.ServerTasksOrErr()
	if IsNotLoaded(err) {
		result, err = b.QueryServerTasks().All(ctx)
	}
	return result, err
}

func (bc *BuildCommit) Build(ctx context.Context) (*Build, error) {
	result, err := bc.Edges.BuildOrErr()
	if IsNotLoaded(err) {
		result, err = bc.QueryBuild().Only(ctx)
	}
	return result, err
}

func (bc *BuildCommit) ServerTasks(ctx context.Context) ([]*ServerTask, error) {
	result, err := bc.Edges.ServerTasksOrErr()
	if IsNotLoaded(err) {
		result, err = bc.QueryServerTasks().All(ctx)
	}
	return result, err
}

func (bc *BuildCommit) PlanDiffs(ctx context.Context) ([]*PlanDiff, error) {
	result, err := bc.Edges.PlanDiffsOrErr()
	if IsNotLoaded(err) {
		result, err = bc.QueryPlanDiffs().All(ctx)
	}
	return result, err
}

func (c *Command) Users(ctx context.Context) ([]*User, error) {
	result, err := c.Edges.UsersOrErr()
	if IsNotLoaded(err) {
		result, err = c.QueryUsers().All(ctx)
	}
	return result, err
}

func (c *Command) Environment(ctx context.Context) (*Environment, error) {
	result, err := c.Edges.EnvironmentOrErr()
	if IsNotLoaded(err) {
		result, err = c.QueryEnvironment().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (c *Competition) DNS(ctx context.Context) ([]*DNS, error) {
	result, err := c.Edges.DNSOrErr()
	if IsNotLoaded(err) {
		result, err = c.QueryDNS().All(ctx)
	}
	return result, err
}

func (c *Competition) Environment(ctx context.Context) (*Environment, error) {
	result, err := c.Edges.EnvironmentOrErr()
	if IsNotLoaded(err) {
		result, err = c.QueryEnvironment().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (c *Competition) Builds(ctx context.Context) ([]*Build, error) {
	result, err := c.Edges.BuildsOrErr()
	if IsNotLoaded(err) {
		result, err = c.QueryBuilds().All(ctx)
	}
	return result, err
}

func (d *DNS) Environments(ctx context.Context) ([]*Environment, error) {
	result, err := d.Edges.EnvironmentsOrErr()
	if IsNotLoaded(err) {
		result, err = d.QueryEnvironments().All(ctx)
	}
	return result, err
}

func (d *DNS) Competitions(ctx context.Context) ([]*Competition, error) {
	result, err := d.Edges.CompetitionsOrErr()
	if IsNotLoaded(err) {
		result, err = d.QueryCompetitions().All(ctx)
	}
	return result, err
}

func (dr *DNSRecord) Environment(ctx context.Context) (*Environment, error) {
	result, err := dr.Edges.EnvironmentOrErr()
	if IsNotLoaded(err) {
		result, err = dr.QueryEnvironment().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (d *Disk) Host(ctx context.Context) (*Host, error) {
	result, err := d.Edges.HostOrErr()
	if IsNotLoaded(err) {
		result, err = d.QueryHost().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (e *Environment) Users(ctx context.Context) ([]*User, error) {
	result, err := e.Edges.UsersOrErr()
	if IsNotLoaded(err) {
		result, err = e.QueryUsers().All(ctx)
	}
	return result, err
}

func (e *Environment) Hosts(ctx context.Context) ([]*Host, error) {
	result, err := e.Edges.HostsOrErr()
	if IsNotLoaded(err) {
		result, err = e.QueryHosts().All(ctx)
	}
	return result, err
}

func (e *Environment) Competitions(ctx context.Context) ([]*Competition, error) {
	result, err := e.Edges.CompetitionsOrErr()
	if IsNotLoaded(err) {
		result, err = e.QueryCompetitions().All(ctx)
	}
	return result, err
}

func (e *Environment) Identities(ctx context.Context) ([]*Identity, error) {
	result, err := e.Edges.IdentitiesOrErr()
	if IsNotLoaded(err) {
		result, err = e.QueryIdentities().All(ctx)
	}
	return result, err
}

func (e *Environment) Commands(ctx context.Context) ([]*Command, error) {
	result, err := e.Edges.CommandsOrErr()
	if IsNotLoaded(err) {
		result, err = e.QueryCommands().All(ctx)
	}
	return result, err
}

func (e *Environment) Scripts(ctx context.Context) ([]*Script, error) {
	result, err := e.Edges.ScriptsOrErr()
	if IsNotLoaded(err) {
		result, err = e.QueryScripts().All(ctx)
	}
	return result, err
}

func (e *Environment) FileDownloads(ctx context.Context) ([]*FileDownload, error) {
	result, err := e.Edges.FileDownloadsOrErr()
	if IsNotLoaded(err) {
		result, err = e.QueryFileDownloads().All(ctx)
	}
	return result, err
}

func (e *Environment) FileDeletes(ctx context.Context) ([]*FileDelete, error) {
	result, err := e.Edges.FileDeletesOrErr()
	if IsNotLoaded(err) {
		result, err = e.QueryFileDeletes().All(ctx)
	}
	return result, err
}

func (e *Environment) FileExtracts(ctx context.Context) ([]*FileExtract, error) {
	result, err := e.Edges.FileExtractsOrErr()
	if IsNotLoaded(err) {
		result, err = e.QueryFileExtracts().All(ctx)
	}
	return result, err
}

func (e *Environment) IncludedNetworks(ctx context.Context) ([]*IncludedNetwork, error) {
	result, err := e.Edges.IncludedNetworksOrErr()
	if IsNotLoaded(err) {
		result, err = e.QueryIncludedNetworks().All(ctx)
	}
	return result, err
}

func (e *Environment) Findings(ctx context.Context) ([]*Finding, error) {
	result, err := e.Edges.FindingsOrErr()
	if IsNotLoaded(err) {
		result, err = e.QueryFindings().All(ctx)
	}
	return result, err
}

func (e *Environment) DNSRecords(ctx context.Context) ([]*DNSRecord, error) {
	result, err := e.Edges.DNSRecordsOrErr()
	if IsNotLoaded(err) {
		result, err = e.QueryDNSRecords().All(ctx)
	}
	return result, err
}

func (e *Environment) DNS(ctx context.Context) ([]*DNS, error) {
	result, err := e.Edges.DNSOrErr()
	if IsNotLoaded(err) {
		result, err = e.QueryDNS().All(ctx)
	}
	return result, err
}

func (e *Environment) Networks(ctx context.Context) ([]*Network, error) {
	result, err := e.Edges.NetworksOrErr()
	if IsNotLoaded(err) {
		result, err = e.QueryNetworks().All(ctx)
	}
	return result, err
}

func (e *Environment) HostDependencies(ctx context.Context) ([]*HostDependency, error) {
	result, err := e.Edges.HostDependenciesOrErr()
	if IsNotLoaded(err) {
		result, err = e.QueryHostDependencies().All(ctx)
	}
	return result, err
}

func (e *Environment) Ansibles(ctx context.Context) ([]*Ansible, error) {
	result, err := e.Edges.AnsiblesOrErr()
	if IsNotLoaded(err) {
		result, err = e.QueryAnsibles().All(ctx)
	}
	return result, err
}

func (e *Environment) ScheduledSteps(ctx context.Context) ([]*ScheduledStep, error) {
	result, err := e.Edges.ScheduledStepsOrErr()
	if IsNotLoaded(err) {
		result, err = e.QueryScheduledSteps().All(ctx)
	}
	return result, err
}

func (e *Environment) Builds(ctx context.Context) ([]*Build, error) {
	result, err := e.Edges.BuildsOrErr()
	if IsNotLoaded(err) {
		result, err = e.QueryBuilds().All(ctx)
	}
	return result, err
}

func (e *Environment) Repositories(ctx context.Context) ([]*Repository, error) {
	result, err := e.Edges.RepositoriesOrErr()
	if IsNotLoaded(err) {
		result, err = e.QueryRepositories().All(ctx)
	}
	return result, err
}

func (e *Environment) ServerTasks(ctx context.Context) ([]*ServerTask, error) {
	result, err := e.Edges.ServerTasksOrErr()
	if IsNotLoaded(err) {
		result, err = e.QueryServerTasks().All(ctx)
	}
	return result, err
}

func (fd *FileDelete) Environment(ctx context.Context) (*Environment, error) {
	result, err := fd.Edges.EnvironmentOrErr()
	if IsNotLoaded(err) {
		result, err = fd.QueryEnvironment().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (fd *FileDownload) Environment(ctx context.Context) (*Environment, error) {
	result, err := fd.Edges.EnvironmentOrErr()
	if IsNotLoaded(err) {
		result, err = fd.QueryEnvironment().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (fe *FileExtract) Environment(ctx context.Context) (*Environment, error) {
	result, err := fe.Edges.EnvironmentOrErr()
	if IsNotLoaded(err) {
		result, err = fe.QueryEnvironment().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (f *Finding) Users(ctx context.Context) ([]*User, error) {
	result, err := f.Edges.UsersOrErr()
	if IsNotLoaded(err) {
		result, err = f.QueryUsers().All(ctx)
	}
	return result, err
}

func (f *Finding) Host(ctx context.Context) (*Host, error) {
	result, err := f.Edges.HostOrErr()
	if IsNotLoaded(err) {
		result, err = f.QueryHost().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (f *Finding) Script(ctx context.Context) (*Script, error) {
	result, err := f.Edges.ScriptOrErr()
	if IsNotLoaded(err) {
		result, err = f.QueryScript().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (f *Finding) Environment(ctx context.Context) (*Environment, error) {
	result, err := f.Edges.EnvironmentOrErr()
	if IsNotLoaded(err) {
		result, err = f.QueryEnvironment().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (gfm *GinFileMiddleware) ProvisionedHost(ctx context.Context) (*ProvisionedHost, error) {
	result, err := gfm.Edges.ProvisionedHostOrErr()
	if IsNotLoaded(err) {
		result, err = gfm.QueryProvisionedHost().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (gfm *GinFileMiddleware) ProvisioningStep(ctx context.Context) (*ProvisioningStep, error) {
	result, err := gfm.Edges.ProvisioningStepOrErr()
	if IsNotLoaded(err) {
		result, err = gfm.QueryProvisioningStep().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (gfm *GinFileMiddleware) ProvisioningScheduledStep(ctx context.Context) (*ProvisioningScheduledStep, error) {
	result, err := gfm.Edges.ProvisioningScheduledStepOrErr()
	if IsNotLoaded(err) {
		result, err = gfm.QueryProvisioningScheduledStep().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (h *Host) Disk(ctx context.Context) (*Disk, error) {
	result, err := h.Edges.DiskOrErr()
	if IsNotLoaded(err) {
		result, err = h.QueryDisk().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (h *Host) Users(ctx context.Context) ([]*User, error) {
	result, err := h.Edges.UsersOrErr()
	if IsNotLoaded(err) {
		result, err = h.QueryUsers().All(ctx)
	}
	return result, err
}

func (h *Host) Environment(ctx context.Context) (*Environment, error) {
	result, err := h.Edges.EnvironmentOrErr()
	if IsNotLoaded(err) {
		result, err = h.QueryEnvironment().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (h *Host) IncludedNetworks(ctx context.Context) ([]*IncludedNetwork, error) {
	result, err := h.Edges.IncludedNetworksOrErr()
	if IsNotLoaded(err) {
		result, err = h.QueryIncludedNetworks().All(ctx)
	}
	return result, err
}

func (h *Host) DependOnHostDependency(ctx context.Context) ([]*HostDependency, error) {
	result, err := h.Edges.DependOnHostDependencyOrErr()
	if IsNotLoaded(err) {
		result, err = h.QueryDependOnHostDependency().All(ctx)
	}
	return result, err
}

func (h *Host) RequiredByHostDependency(ctx context.Context) ([]*HostDependency, error) {
	result, err := h.Edges.RequiredByHostDependencyOrErr()
	if IsNotLoaded(err) {
		result, err = h.QueryRequiredByHostDependency().All(ctx)
	}
	return result, err
}

func (hd *HostDependency) DependOn(ctx context.Context) (*Host, error) {
	result, err := hd.Edges.DependOnOrErr()
	if IsNotLoaded(err) {
		result, err = hd.QueryDependOn().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (hd *HostDependency) RequiredBy(ctx context.Context) (*Host, error) {
	result, err := hd.Edges.RequiredByOrErr()
	if IsNotLoaded(err) {
		result, err = hd.QueryRequiredBy().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (hd *HostDependency) Network(ctx context.Context) (*Network, error) {
	result, err := hd.Edges.NetworkOrErr()
	if IsNotLoaded(err) {
		result, err = hd.QueryNetwork().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (hd *HostDependency) Environment(ctx context.Context) (*Environment, error) {
	result, err := hd.Edges.EnvironmentOrErr()
	if IsNotLoaded(err) {
		result, err = hd.QueryEnvironment().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (i *Identity) Environment(ctx context.Context) (*Environment, error) {
	result, err := i.Edges.EnvironmentOrErr()
	if IsNotLoaded(err) {
		result, err = i.QueryEnvironment().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (in *IncludedNetwork) Tags(ctx context.Context) ([]*Tag, error) {
	result, err := in.Edges.TagsOrErr()
	if IsNotLoaded(err) {
		result, err = in.QueryTags().All(ctx)
	}
	return result, err
}

func (in *IncludedNetwork) Hosts(ctx context.Context) ([]*Host, error) {
	result, err := in.Edges.HostsOrErr()
	if IsNotLoaded(err) {
		result, err = in.QueryHosts().All(ctx)
	}
	return result, err
}

func (in *IncludedNetwork) Network(ctx context.Context) (*Network, error) {
	result, err := in.Edges.NetworkOrErr()
	if IsNotLoaded(err) {
		result, err = in.QueryNetwork().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (in *IncludedNetwork) Environments(ctx context.Context) ([]*Environment, error) {
	result, err := in.Edges.EnvironmentsOrErr()
	if IsNotLoaded(err) {
		result, err = in.QueryEnvironments().All(ctx)
	}
	return result, err
}

func (n *Network) Environment(ctx context.Context) (*Environment, error) {
	result, err := n.Edges.EnvironmentOrErr()
	if IsNotLoaded(err) {
		result, err = n.QueryEnvironment().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (n *Network) HostDependencies(ctx context.Context) ([]*HostDependency, error) {
	result, err := n.Edges.HostDependenciesOrErr()
	if IsNotLoaded(err) {
		result, err = n.QueryHostDependencies().All(ctx)
	}
	return result, err
}

func (n *Network) IncludedNetworks(ctx context.Context) ([]*IncludedNetwork, error) {
	result, err := n.Edges.IncludedNetworksOrErr()
	if IsNotLoaded(err) {
		result, err = n.QueryIncludedNetworks().All(ctx)
	}
	return result, err
}

func (pl *Plan) PrevPlans(ctx context.Context) ([]*Plan, error) {
	result, err := pl.Edges.PrevPlansOrErr()
	if IsNotLoaded(err) {
		result, err = pl.QueryPrevPlans().All(ctx)
	}
	return result, err
}

func (pl *Plan) NextPlans(ctx context.Context) ([]*Plan, error) {
	result, err := pl.Edges.NextPlansOrErr()
	if IsNotLoaded(err) {
		result, err = pl.QueryNextPlans().All(ctx)
	}
	return result, err
}

func (pl *Plan) Build(ctx context.Context) (*Build, error) {
	result, err := pl.Edges.BuildOrErr()
	if IsNotLoaded(err) {
		result, err = pl.QueryBuild().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pl *Plan) Team(ctx context.Context) (*Team, error) {
	result, err := pl.Edges.TeamOrErr()
	if IsNotLoaded(err) {
		result, err = pl.QueryTeam().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pl *Plan) ProvisionedNetwork(ctx context.Context) (*ProvisionedNetwork, error) {
	result, err := pl.Edges.ProvisionedNetworkOrErr()
	if IsNotLoaded(err) {
		result, err = pl.QueryProvisionedNetwork().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pl *Plan) ProvisionedHost(ctx context.Context) (*ProvisionedHost, error) {
	result, err := pl.Edges.ProvisionedHostOrErr()
	if IsNotLoaded(err) {
		result, err = pl.QueryProvisionedHost().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pl *Plan) ProvisioningStep(ctx context.Context) (*ProvisioningStep, error) {
	result, err := pl.Edges.ProvisioningStepOrErr()
	if IsNotLoaded(err) {
		result, err = pl.QueryProvisioningStep().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pl *Plan) ProvisioningScheduledStep(ctx context.Context) (*ProvisioningScheduledStep, error) {
	result, err := pl.Edges.ProvisioningScheduledStepOrErr()
	if IsNotLoaded(err) {
		result, err = pl.QueryProvisioningScheduledStep().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pl *Plan) Status(ctx context.Context) (*Status, error) {
	result, err := pl.Edges.StatusOrErr()
	if IsNotLoaded(err) {
		result, err = pl.QueryStatus().Only(ctx)
	}
	return result, err
}

func (pl *Plan) PlanDiffs(ctx context.Context) ([]*PlanDiff, error) {
	result, err := pl.Edges.PlanDiffsOrErr()
	if IsNotLoaded(err) {
		result, err = pl.QueryPlanDiffs().All(ctx)
	}
	return result, err
}

func (pd *PlanDiff) BuildCommit(ctx context.Context) (*BuildCommit, error) {
	result, err := pd.Edges.BuildCommitOrErr()
	if IsNotLoaded(err) {
		result, err = pd.QueryBuildCommit().Only(ctx)
	}
	return result, err
}

func (pd *PlanDiff) Plan(ctx context.Context) (*Plan, error) {
	result, err := pd.Edges.PlanOrErr()
	if IsNotLoaded(err) {
		result, err = pd.QueryPlan().Only(ctx)
	}
	return result, err
}

func (ph *ProvisionedHost) Status(ctx context.Context) (*Status, error) {
	result, err := ph.Edges.StatusOrErr()
	if IsNotLoaded(err) {
		result, err = ph.QueryStatus().Only(ctx)
	}
	return result, err
}

func (ph *ProvisionedHost) ProvisionedNetwork(ctx context.Context) (*ProvisionedNetwork, error) {
	result, err := ph.Edges.ProvisionedNetworkOrErr()
	if IsNotLoaded(err) {
		result, err = ph.QueryProvisionedNetwork().Only(ctx)
	}
	return result, err
}

func (ph *ProvisionedHost) Host(ctx context.Context) (*Host, error) {
	result, err := ph.Edges.HostOrErr()
	if IsNotLoaded(err) {
		result, err = ph.QueryHost().Only(ctx)
	}
	return result, err
}

func (ph *ProvisionedHost) EndStepPlan(ctx context.Context) (*Plan, error) {
	result, err := ph.Edges.EndStepPlanOrErr()
	if IsNotLoaded(err) {
		result, err = ph.QueryEndStepPlan().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (ph *ProvisionedHost) Build(ctx context.Context) (*Build, error) {
	result, err := ph.Edges.BuildOrErr()
	if IsNotLoaded(err) {
		result, err = ph.QueryBuild().Only(ctx)
	}
	return result, err
}

func (ph *ProvisionedHost) ProvisioningSteps(ctx context.Context) ([]*ProvisioningStep, error) {
	result, err := ph.Edges.ProvisioningStepsOrErr()
	if IsNotLoaded(err) {
		result, err = ph.QueryProvisioningSteps().All(ctx)
	}
	return result, err
}

func (ph *ProvisionedHost) ProvisioningScheduledSteps(ctx context.Context) ([]*ProvisioningScheduledStep, error) {
	result, err := ph.Edges.ProvisioningScheduledStepsOrErr()
	if IsNotLoaded(err) {
		result, err = ph.QueryProvisioningScheduledSteps().All(ctx)
	}
	return result, err
}

func (ph *ProvisionedHost) AgentStatuses(ctx context.Context) ([]*AgentStatus, error) {
	result, err := ph.Edges.AgentStatusesOrErr()
	if IsNotLoaded(err) {
		result, err = ph.QueryAgentStatuses().All(ctx)
	}
	return result, err
}

func (ph *ProvisionedHost) AgentTasks(ctx context.Context) ([]*AgentTask, error) {
	result, err := ph.Edges.AgentTasksOrErr()
	if IsNotLoaded(err) {
		result, err = ph.QueryAgentTasks().All(ctx)
	}
	return result, err
}

func (ph *ProvisionedHost) Plan(ctx context.Context) (*Plan, error) {
	result, err := ph.Edges.PlanOrErr()
	if IsNotLoaded(err) {
		result, err = ph.QueryPlan().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (ph *ProvisionedHost) GinFileMiddleware(ctx context.Context) (*GinFileMiddleware, error) {
	result, err := ph.Edges.GinFileMiddlewareOrErr()
	if IsNotLoaded(err) {
		result, err = ph.QueryGinFileMiddleware().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pn *ProvisionedNetwork) Status(ctx context.Context) (*Status, error) {
	result, err := pn.Edges.StatusOrErr()
	if IsNotLoaded(err) {
		result, err = pn.QueryStatus().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pn *ProvisionedNetwork) Network(ctx context.Context) (*Network, error) {
	result, err := pn.Edges.NetworkOrErr()
	if IsNotLoaded(err) {
		result, err = pn.QueryNetwork().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pn *ProvisionedNetwork) Build(ctx context.Context) (*Build, error) {
	result, err := pn.Edges.BuildOrErr()
	if IsNotLoaded(err) {
		result, err = pn.QueryBuild().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pn *ProvisionedNetwork) Team(ctx context.Context) (*Team, error) {
	result, err := pn.Edges.TeamOrErr()
	if IsNotLoaded(err) {
		result, err = pn.QueryTeam().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pn *ProvisionedNetwork) ProvisionedHosts(ctx context.Context) ([]*ProvisionedHost, error) {
	result, err := pn.Edges.ProvisionedHostsOrErr()
	if IsNotLoaded(err) {
		result, err = pn.QueryProvisionedHosts().All(ctx)
	}
	return result, err
}

func (pn *ProvisionedNetwork) Plan(ctx context.Context) (*Plan, error) {
	result, err := pn.Edges.PlanOrErr()
	if IsNotLoaded(err) {
		result, err = pn.QueryPlan().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pss *ProvisioningScheduledStep) Status(ctx context.Context) (*Status, error) {
	result, err := pss.Edges.StatusOrErr()
	if IsNotLoaded(err) {
		result, err = pss.QueryStatus().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pss *ProvisioningScheduledStep) ScheduledStep(ctx context.Context) (*ScheduledStep, error) {
	result, err := pss.Edges.ScheduledStepOrErr()
	if IsNotLoaded(err) {
		result, err = pss.QueryScheduledStep().Only(ctx)
	}
	return result, err
}

func (pss *ProvisioningScheduledStep) ProvisionedHost(ctx context.Context) (*ProvisionedHost, error) {
	result, err := pss.Edges.ProvisionedHostOrErr()
	if IsNotLoaded(err) {
		result, err = pss.QueryProvisionedHost().Only(ctx)
	}
	return result, err
}

func (pss *ProvisioningScheduledStep) Script(ctx context.Context) (*Script, error) {
	result, err := pss.Edges.ScriptOrErr()
	if IsNotLoaded(err) {
		result, err = pss.QueryScript().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pss *ProvisioningScheduledStep) Command(ctx context.Context) (*Command, error) {
	result, err := pss.Edges.CommandOrErr()
	if IsNotLoaded(err) {
		result, err = pss.QueryCommand().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pss *ProvisioningScheduledStep) DNSRecord(ctx context.Context) (*DNSRecord, error) {
	result, err := pss.Edges.DNSRecordOrErr()
	if IsNotLoaded(err) {
		result, err = pss.QueryDNSRecord().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pss *ProvisioningScheduledStep) FileDelete(ctx context.Context) (*FileDelete, error) {
	result, err := pss.Edges.FileDeleteOrErr()
	if IsNotLoaded(err) {
		result, err = pss.QueryFileDelete().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pss *ProvisioningScheduledStep) FileDownload(ctx context.Context) (*FileDownload, error) {
	result, err := pss.Edges.FileDownloadOrErr()
	if IsNotLoaded(err) {
		result, err = pss.QueryFileDownload().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pss *ProvisioningScheduledStep) FileExtract(ctx context.Context) (*FileExtract, error) {
	result, err := pss.Edges.FileExtractOrErr()
	if IsNotLoaded(err) {
		result, err = pss.QueryFileExtract().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pss *ProvisioningScheduledStep) Ansible(ctx context.Context) (*Ansible, error) {
	result, err := pss.Edges.AnsibleOrErr()
	if IsNotLoaded(err) {
		result, err = pss.QueryAnsible().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pss *ProvisioningScheduledStep) AgentTasks(ctx context.Context) ([]*AgentTask, error) {
	result, err := pss.Edges.AgentTasksOrErr()
	if IsNotLoaded(err) {
		result, err = pss.QueryAgentTasks().All(ctx)
	}
	return result, err
}

func (pss *ProvisioningScheduledStep) Plan(ctx context.Context) (*Plan, error) {
	result, err := pss.Edges.PlanOrErr()
	if IsNotLoaded(err) {
		result, err = pss.QueryPlan().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (pss *ProvisioningScheduledStep) GinFileMiddleware(ctx context.Context) (*GinFileMiddleware, error) {
	result, err := pss.Edges.GinFileMiddlewareOrErr()
	if IsNotLoaded(err) {
		result, err = pss.QueryGinFileMiddleware().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (ps *ProvisioningStep) Status(ctx context.Context) (*Status, error) {
	result, err := ps.Edges.StatusOrErr()
	if IsNotLoaded(err) {
		result, err = ps.QueryStatus().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (ps *ProvisioningStep) ProvisionedHost(ctx context.Context) (*ProvisionedHost, error) {
	result, err := ps.Edges.ProvisionedHostOrErr()
	if IsNotLoaded(err) {
		result, err = ps.QueryProvisionedHost().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (ps *ProvisioningStep) Script(ctx context.Context) (*Script, error) {
	result, err := ps.Edges.ScriptOrErr()
	if IsNotLoaded(err) {
		result, err = ps.QueryScript().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (ps *ProvisioningStep) Command(ctx context.Context) (*Command, error) {
	result, err := ps.Edges.CommandOrErr()
	if IsNotLoaded(err) {
		result, err = ps.QueryCommand().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (ps *ProvisioningStep) DNSRecord(ctx context.Context) (*DNSRecord, error) {
	result, err := ps.Edges.DNSRecordOrErr()
	if IsNotLoaded(err) {
		result, err = ps.QueryDNSRecord().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (ps *ProvisioningStep) FileDelete(ctx context.Context) (*FileDelete, error) {
	result, err := ps.Edges.FileDeleteOrErr()
	if IsNotLoaded(err) {
		result, err = ps.QueryFileDelete().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (ps *ProvisioningStep) FileDownload(ctx context.Context) (*FileDownload, error) {
	result, err := ps.Edges.FileDownloadOrErr()
	if IsNotLoaded(err) {
		result, err = ps.QueryFileDownload().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (ps *ProvisioningStep) FileExtract(ctx context.Context) (*FileExtract, error) {
	result, err := ps.Edges.FileExtractOrErr()
	if IsNotLoaded(err) {
		result, err = ps.QueryFileExtract().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (ps *ProvisioningStep) Ansible(ctx context.Context) (*Ansible, error) {
	result, err := ps.Edges.AnsibleOrErr()
	if IsNotLoaded(err) {
		result, err = ps.QueryAnsible().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (ps *ProvisioningStep) Plan(ctx context.Context) (*Plan, error) {
	result, err := ps.Edges.PlanOrErr()
	if IsNotLoaded(err) {
		result, err = ps.QueryPlan().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (ps *ProvisioningStep) AgentTasks(ctx context.Context) ([]*AgentTask, error) {
	result, err := ps.Edges.AgentTasksOrErr()
	if IsNotLoaded(err) {
		result, err = ps.QueryAgentTasks().All(ctx)
	}
	return result, err
}

func (ps *ProvisioningStep) GinFileMiddleware(ctx context.Context) (*GinFileMiddleware, error) {
	result, err := ps.Edges.GinFileMiddlewareOrErr()
	if IsNotLoaded(err) {
		result, err = ps.QueryGinFileMiddleware().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (rc *RepoCommit) Repository(ctx context.Context) (*Repository, error) {
	result, err := rc.Edges.RepositoryOrErr()
	if IsNotLoaded(err) {
		result, err = rc.QueryRepository().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (r *Repository) Environments(ctx context.Context) ([]*Environment, error) {
	result, err := r.Edges.EnvironmentsOrErr()
	if IsNotLoaded(err) {
		result, err = r.QueryEnvironments().All(ctx)
	}
	return result, err
}

func (r *Repository) RepoCommits(ctx context.Context) ([]*RepoCommit, error) {
	result, err := r.Edges.RepoCommitsOrErr()
	if IsNotLoaded(err) {
		result, err = r.QueryRepoCommits().All(ctx)
	}
	return result, err
}

func (ss *ScheduledStep) Environment(ctx context.Context) (*Environment, error) {
	result, err := ss.Edges.EnvironmentOrErr()
	if IsNotLoaded(err) {
		result, err = ss.QueryEnvironment().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (s *Script) Users(ctx context.Context) ([]*User, error) {
	result, err := s.Edges.UsersOrErr()
	if IsNotLoaded(err) {
		result, err = s.QueryUsers().All(ctx)
	}
	return result, err
}

func (s *Script) Findings(ctx context.Context) ([]*Finding, error) {
	result, err := s.Edges.FindingsOrErr()
	if IsNotLoaded(err) {
		result, err = s.QueryFindings().All(ctx)
	}
	return result, err
}

func (s *Script) Environment(ctx context.Context) (*Environment, error) {
	result, err := s.Edges.EnvironmentOrErr()
	if IsNotLoaded(err) {
		result, err = s.QueryEnvironment().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (st *ServerTask) AuthUser(ctx context.Context) (*AuthUser, error) {
	result, err := st.Edges.AuthUserOrErr()
	if IsNotLoaded(err) {
		result, err = st.QueryAuthUser().Only(ctx)
	}
	return result, err
}

func (st *ServerTask) Status(ctx context.Context) (*Status, error) {
	result, err := st.Edges.StatusOrErr()
	if IsNotLoaded(err) {
		result, err = st.QueryStatus().Only(ctx)
	}
	return result, err
}

func (st *ServerTask) Environment(ctx context.Context) (*Environment, error) {
	result, err := st.Edges.EnvironmentOrErr()
	if IsNotLoaded(err) {
		result, err = st.QueryEnvironment().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (st *ServerTask) Build(ctx context.Context) (*Build, error) {
	result, err := st.Edges.BuildOrErr()
	if IsNotLoaded(err) {
		result, err = st.QueryBuild().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (st *ServerTask) BuildCommit(ctx context.Context) (*BuildCommit, error) {
	result, err := st.Edges.BuildCommitOrErr()
	if IsNotLoaded(err) {
		result, err = st.QueryBuildCommit().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (st *ServerTask) GinFileMiddleware(ctx context.Context) ([]*GinFileMiddleware, error) {
	result, err := st.Edges.GinFileMiddlewareOrErr()
	if IsNotLoaded(err) {
		result, err = st.QueryGinFileMiddleware().All(ctx)
	}
	return result, err
}

func (s *Status) Build(ctx context.Context) (*Build, error) {
	result, err := s.Edges.BuildOrErr()
	if IsNotLoaded(err) {
		result, err = s.QueryBuild().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (s *Status) ProvisionedNetwork(ctx context.Context) (*ProvisionedNetwork, error) {
	result, err := s.Edges.ProvisionedNetworkOrErr()
	if IsNotLoaded(err) {
		result, err = s.QueryProvisionedNetwork().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (s *Status) ProvisionedHost(ctx context.Context) (*ProvisionedHost, error) {
	result, err := s.Edges.ProvisionedHostOrErr()
	if IsNotLoaded(err) {
		result, err = s.QueryProvisionedHost().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (s *Status) ProvisioningStep(ctx context.Context) (*ProvisioningStep, error) {
	result, err := s.Edges.ProvisioningStepOrErr()
	if IsNotLoaded(err) {
		result, err = s.QueryProvisioningStep().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (s *Status) Team(ctx context.Context) (*Team, error) {
	result, err := s.Edges.TeamOrErr()
	if IsNotLoaded(err) {
		result, err = s.QueryTeam().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (s *Status) Plan(ctx context.Context) (*Plan, error) {
	result, err := s.Edges.PlanOrErr()
	if IsNotLoaded(err) {
		result, err = s.QueryPlan().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (s *Status) ServerTask(ctx context.Context) (*ServerTask, error) {
	result, err := s.Edges.ServerTaskOrErr()
	if IsNotLoaded(err) {
		result, err = s.QueryServerTask().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (s *Status) AdhocPlan(ctx context.Context) (*AdhocPlan, error) {
	result, err := s.Edges.AdhocPlanOrErr()
	if IsNotLoaded(err) {
		result, err = s.QueryAdhocPlan().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (s *Status) ProvisioningScheduledStep(ctx context.Context) (*ProvisioningScheduledStep, error) {
	result, err := s.Edges.ProvisioningScheduledStepOrErr()
	if IsNotLoaded(err) {
		result, err = s.QueryProvisioningScheduledStep().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (t *Team) Build(ctx context.Context) (*Build, error) {
	result, err := t.Edges.BuildOrErr()
	if IsNotLoaded(err) {
		result, err = t.QueryBuild().Only(ctx)
	}
	return result, err
}

func (t *Team) Status(ctx context.Context) (*Status, error) {
	result, err := t.Edges.StatusOrErr()
	if IsNotLoaded(err) {
		result, err = t.QueryStatus().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (t *Team) ProvisionedNetworks(ctx context.Context) ([]*ProvisionedNetwork, error) {
	result, err := t.Edges.ProvisionedNetworksOrErr()
	if IsNotLoaded(err) {
		result, err = t.QueryProvisionedNetworks().All(ctx)
	}
	return result, err
}

func (t *Team) Plan(ctx context.Context) (*Plan, error) {
	result, err := t.Edges.PlanOrErr()
	if IsNotLoaded(err) {
		result, err = t.QueryPlan().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (t *Token) AuthUser(ctx context.Context) (*AuthUser, error) {
	result, err := t.Edges.AuthUserOrErr()
	if IsNotLoaded(err) {
		result, err = t.QueryAuthUser().Only(ctx)
	}
	return result, err
}

func (u *User) UserToTag(ctx context.Context) ([]*Tag, error) {
	result, err := u.Edges.UserToTagOrErr()
	if IsNotLoaded(err) {
		result, err = u.QueryUserToTag().All(ctx)
	}
	return result, err
}

func (u *User) UserToEnvironment(ctx context.Context) ([]*Environment, error) {
	result, err := u.Edges.UserToEnvironmentOrErr()
	if IsNotLoaded(err) {
		result, err = u.QueryUserToEnvironment().All(ctx)
	}
	return result, err
}
