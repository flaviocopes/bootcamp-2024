import type {
  ProjectsRecord,
  ProjectsResponse,
  TasksRecord,
  TasksResponse,
  TeamsRecord,
  TypedPocketBase,
  TeamsResponse,
  UsersResponse,
  InvitesResponse,
  ActivitiesResponse,
} from '@src/data/pocketbase-types'

import { getUserObjectFromDb } from '@lib/auth'

type TexpandProject = {
  project?: ProjectsResponse
}

type TexpandMembers = {
  members: UsersResponse[]
}

type TexpandTeam = {
  team: TeamsResponse
}

type TexpandUser = {
  user: UsersResponse
}

export async function getProjects({
  pb,
  team_id,
}: {
  pb: TypedPocketBase
  team_id?: string
}) {
  const options = { filter: 'team = ""' }

  if (team_id) {
    options.filter = `team = "${team_id as string}"`
  }

  const projects = await pb
    .collection('projects')

    .getFullList(options)

  return projects.sort((a, b) => getStatus(a) - getStatus(b))
}

export async function addProject(
  pb: TypedPocketBase,
  name: string,
  team_id?: string
) {
  const newProject = await pb.collection('projects').create({
    name,
    created_by: pb.authStore.model?.id,
    status: 'not started',
    team: team_id,
  })

  return newProject
}

export async function getProject(pb: TypedPocketBase, id: string) {
  const project = await pb.collection('projects').getOne(id)

  return project
}

export async function addTask(
  pb: TypedPocketBase,
  project_id: string,
  text: string
) {
  const newTask = await pb.collection('tasks').create({
    project: project_id,
    created_by: pb.authStore.model?.id,
    text,
  })

  return newTask
}

export async function getTasks({
  pb,
  project_id = null,
  done = false,
}): Promise<TasksResponse<TexpandProject>[]> {
  const options = {
    filter: '',
    expand: 'project',
    sort: '-starred_on, created',
  }

  let filter = `completed = ${done}`
  filter += ` && project = "${project_id}"`
  options.filter = filter

  let tasks: TasksResponse<TexpandProject>[] = []
  tasks = await pb.collection('tasks').getFullList(options)

  return tasks
}

function getStatus(project: ProjectsResponse) {
  switch (project.status) {
    case 'not started':
      return 7
    case 'on hold':
      return 6
    case 'started':
      return 5
    case 'in progress':
      return 4
    case 'almost finished':
      return 3
    case 'ongoing':
      return 2
    case 'done':
      return 1
    default:
      return 0
  }
}

export async function deleteProject(pb: TypedPocketBase, id: string) {
  await pb.collection('projects').delete(id)
}

export async function updateProject(
  pb: TypedPocketBase,
  id: string,
  data: ProjectsRecord
) {
  await pb.collection('projects').update(id, data)
}

export async function deleteTask(pb: TypedPocketBase, id: string) {
  await pb.collection('tasks').delete(id)
}

export async function updateTask(
  pb: TypedPocketBase,
  id: string,
  data: TasksRecord
) {
  await pb.collection('tasks').update(id, data)
}

export async function getStarredTasks({
  pb,
  team_id = null,
}): Promise<TasksResponse<TexpandProject>[]> {
  const options = {
    sort: '-starred_on',
    filter: 'starred = true && completed = false',
    expand: 'project',
  }

  if (team_id) {
    options.filter += ` && project.team = "${team_id}"`
  } else {
    options.filter += ` && project.team = ""`
  }

  const tasks: TasksResponse<TexpandProject>[] = await pb
    .collection('tasks')
    .getFullList(options)

  return tasks
}

export function processImages(pb: TypedPocketBase, task: TasksResponse) {
  type ImageItem = {
    name: string
    url: string
    url_larger: string
  }

  const images: ImageItem[] = []

  task.images?.map((image: string) => {
    images.push({
      name: image,
      url: pb.files.getUrl(task, image, {
        thumb: '0x200',
      }),
      url_larger: pb.files.getUrl(task, image, {
        thumb: '0x800',
      }),
    })
  })

  return images
}

export async function addTeam(pb: TypedPocketBase, name: string) {
  let team = await pb.collection('teams').create({
    name,
    created_by: pb.authStore.model?.id,
    status: 'inactive',
  })

  return team
}

export async function getTeam(pb: TypedPocketBase, id: string) {
  const team = await pb.collection('teams').getOne(id)

  return team
}

export async function userIsTeamOwner(pb: TypedPocketBase, team_id: string) {
  const team = await getTeam(pb, team_id)
  if (team.created_by === pb.authStore.model?.id) {
    return true
  }
  return false
}

export async function getTeams(pb: TypedPocketBase) {
  const teams = await pb.collection('teams').getFullList()
  return teams
}

export async function deleteTeam(pb: TypedPocketBase, id: string) {
  return await pb.collection('teams').delete(id)
}

export async function updateTeam(
  pb: TypedPocketBase,
  id: string,
  data: TeamsRecord
) {
  await pb.collection('teams').update(id, data)
}

export async function getMembersOfTeam(pb: TypedPocketBase, team_id: string) {
  const team: TeamsResponse<TexpandMembers> = await pb
    .collection('teams')
    .getOne(team_id, {
      expand: 'members',
    })

  return team.expand?.members
}

export async function getOwnerOfTeam(pb: TypedPocketBase, team: TeamsResponse) {
  const user: UsersResponse = await pb
    .collection('users')
    .getOne(team.created_by)

  return user
}

export async function getInvitesForTeam(pb: TypedPocketBase, team_id: string) {
  const invites: InvitesResponse[] = await pb
    .collection('invites')
    .getFullList({
      filter: `team = "${team_id}"`,
    })
  return invites
}

export async function addInvite(
  pb: TypedPocketBase,
  team_id: string,
  email: string
) {
  await pb.collection('invites').create({
    team: team_id,
    email,
  })
}

export async function getYourInvites(pb: TypedPocketBase) {
  const options = {
    filter: `email = "${pb.authStore.model?.email}"`,
    expand: 'team',
  }
  const invites: InvitesResponse<TexpandTeam>[] = await pb
    .collection('invites')
    .getFullList(options)

  return invites
}

export async function addMember(
  pb: TypedPocketBase,
  team_id: string,
  person_id: string
) {
  await pb.collection('teams').update(team_id, {
    'members+': person_id,
  })
}

export async function deleteInvite(pb: TypedPocketBase, id: string) {
  await pb.collection('invites').delete(id)
}

export async function getInvite(pb: TypedPocketBase, id: string) {
  const team: InvitesResponse = await pb.collection('invites').getOne(id)

  return team
}

export async function getTask(pb: TypedPocketBase, id: string) {
  const options = {
    expand: 'project',
  }

  const task: TasksResponse<TexpandProject> = await pb
    .collection('tasks')
    .getOne(id, options)

  return task
}

export async function addActivity({
  pb,
  team,
  project,
  text,
  type,
}: {
  pb: TypedPocketBase
  team: string
  project: string
  text: string
  type: string
}) {
  await pb.collection('activities').create({
    team,
    project,
    text,
    type,
    user: pb.authStore.model?.id,
  })
}

export async function getActivities({
  pb,
  team_id,
  project_id,
  user_id,
}: {
  pb: TypedPocketBase
  team_id?: string
  project_id?: string
  user_id?: string
}) {
  const options = {
    filter: '',
    sort: '-created',
    expand: 'team,project,user',
  }

  if (team_id) {
    options.filter += `team = "${team_id}"`
  }
  if (project_id) {
    if (options.filter.length === 0) {
      options.filter += `project = "${project_id}"`
    } else {
      options.filter += ` && project = "${project_id}"`
    }
  }
  if (user_id) {
    if (options.filter.length === 0) {
      options.filter += `user = "${user_id}"`
    } else {
      options.filter += ` && user = "${user_id}"`
    }
  }

  if (!team_id && !project_id && !user_id) {
    //@ts-expect-error
    options.perPage = 100
  }

  //@ts-expect-error
  const activities: ActivitiesResponse<
    TexpandTeam,
    TexpandProject,
    TexpandUser
  >[] = await pb.collection('activities').getFullList(options)

  return activities
}

export async function getAllProjects(pb: TypedPocketBase) {
  const projects = await pb.collection('projects').getFullList()

  return projects.sort((a, b) => getStatus(a) - getStatus(b))
}

export async function getCollaborators(pb: TypedPocketBase) {
  const teams = await getTeams(pb)

  const collaborators: UsersResponse[] = []

  await Promise.all(
    teams.map(async (team) => {
      await Promise.all(
        team.members.map(async (member) => {
          const user = await getUserObjectFromDb(pb, member)
          if (
            !collaborators.find(
              (collaborator) => collaborator.username === user.username
            )
          ) {
            collaborators.push(user)
          }
        })
      )
      collaborators.push(await getOwnerOfTeam(pb, team))
    })
  )

  return collaborators.sort((a, b) => a.username.localeCompare(b.username))
}
