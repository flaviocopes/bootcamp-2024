/**
* This file was @generated using pocketbase-typegen
*/

import type PocketBase from 'pocketbase'
import type { RecordService } from 'pocketbase'

export enum Collections {
	Projects = "projects",
	Tasks = "tasks",
	Teams = "teams",
	Users = "users",
}

// Alias types for improved usability
export type IsoDateString = string
export type RecordIdString = string
export type HTMLString = string

// System fields
export type BaseSystemFields<T = never> = {
	id: RecordIdString
	created: IsoDateString
	updated: IsoDateString
	collectionId: string
	collectionName: Collections
	expand?: T
}

export type AuthSystemFields<T = never> = {
	email: string
	emailVisibility: boolean
	username: string
	verified: boolean
} & BaseSystemFields<T>

// Record types for each collection

export enum ProjectsStatusOptions {
	"not started" = "not started",
	"started" = "started",
	"in progress" = "in progress",
	"almost finished" = "almost finished",
	"done" = "done",
	"ongoing" = "ongoing",
	"on hold" = "on hold",
	"archived" = "archived",
}
export type ProjectsRecord = {
	created_by?: RecordIdString
	name?: string
	status?: ProjectsStatusOptions
}

export type TasksRecord = {
	completed?: boolean
	completed_on?: IsoDateString
	created_by?: RecordIdString
	images?: string[]
	project?: RecordIdString
	starred?: boolean
	starred_on?: IsoDateString
	text?: string
}

export enum TeamsStatusOptions {
	"inactive" = "inactive",
	"active" = "active",
	"freezed" = "freezed",
}
export type TeamsRecord = {
	created_by?: RecordIdString
	members?: RecordIdString[]
	name?: string
	portal_url?: string
	status?: TeamsStatusOptions
	stripe_subscription_id?: string
}

export type UsersRecord = {
	avatar?: string
	name?: string
}

// Response types include system fields and match responses from the PocketBase API
export type ProjectsResponse<Texpand = unknown> = Required<ProjectsRecord> & BaseSystemFields<Texpand>
export type TasksResponse<Texpand = unknown> = Required<TasksRecord> & BaseSystemFields<Texpand>
export type TeamsResponse<Texpand = unknown> = Required<TeamsRecord> & BaseSystemFields<Texpand>
export type UsersResponse<Texpand = unknown> = Required<UsersRecord> & AuthSystemFields<Texpand>

// Types containing all Records and Responses, useful for creating typing helper functions

export type CollectionRecords = {
	projects: ProjectsRecord
	tasks: TasksRecord
	teams: TeamsRecord
	users: UsersRecord
}

export type CollectionResponses = {
	projects: ProjectsResponse
	tasks: TasksResponse
	teams: TeamsResponse
	users: UsersResponse
}

// Type for usage with type asserted PocketBase instance
// https://github.com/pocketbase/js-sdk#specify-typescript-definitions

export type TypedPocketBase = PocketBase & {
	collection(idOrName: 'projects'): RecordService<ProjectsResponse>
	collection(idOrName: 'tasks'): RecordService<TasksResponse>
	collection(idOrName: 'teams'): RecordService<TeamsResponse>
	collection(idOrName: 'users'): RecordService<UsersResponse>
}
