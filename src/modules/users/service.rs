use bcrypt::hash;
use sea_orm::{
  ActiveModelTrait, DatabaseConnection, EntityTrait, ItemsAndPagesNumber, PaginatorTrait,
  QueryOrder, Set,
};
use uuid::Uuid;

use crate::common::config::Config;
use crate::common::errors::ApiError;
use crate::common::pagination::{
  CursorMeta, CursorResponse, PageMeta, PageResponse, PaginatedResponse, PaginationParams,
};
use crate::modules::users::dto::UserDto;
use crate::modules::users::entities::{self, Entity as UserEntity, UserProfile};
use crate::modules::users::enums::UserStatus;

pub async fn index(
  db: &DatabaseConnection,
  params: &PaginationParams,
) -> Result<PaginatedResponse<UserDto>, ApiError> {
  let per_page = params.per_page();

  if params.is_cursor_mode() {
    // Cursor-based pagination
    let cursor = params.cursor.as_deref().unwrap_or_default();
    let cursor_id = Uuid::parse_str(cursor)
      .map_err(|_| ApiError::InvalidRequest("Invalid cursor".to_string()))?;

    // Find cursor item to anchor the keyset on its (created_at, id) tuple
    let cursor_item = UserEntity::find_by_id(cursor_id)
      .one(db)
      .await?
      .ok_or_else(|| ApiError::InvalidRequest("Cursor not found".to_string()))?;

    // Keyset pagination on (created_at, id): fetch per_page + 1 to detect a next page
    let users = UserEntity::find()
      .cursor_by((entities::Column::CreatedAt, entities::Column::Id))
      .into_partial_model::<UserProfile>()
      .after((cursor_item.created_at, cursor_id))
      .first(per_page + 1)
      .all(db)
      .await?;

    let has_next = users.len() as u64 > per_page;
    let items: Vec<UserDto> = users
      .into_iter()
      .take(per_page as usize)
      .map(UserDto::from)
      .collect();

    let next_cursor = if has_next {
      items.last().map(|u| u.id.clone())
    } else {
      None
    };

    Ok(PaginatedResponse::Cursor(CursorResponse {
      data: items,
      meta: CursorMeta {
        per_page,
        next_cursor,
      },
    }))
  } else {
    // Page-based pagination
    let page = params.page();

    let paginator = UserEntity::find()
      .order_by_asc(entities::Column::CreatedAt)
      .order_by_asc(entities::Column::Id)
      .into_partial_model::<UserProfile>()
      .paginate(db, per_page);

    let ItemsAndPagesNumber {
      number_of_items: total,
      number_of_pages: total_pages,
    } = paginator.num_items_and_pages().await?;
    let users = paginator.fetch_page(page - 1).await?;

    let items: Vec<UserDto> = users.into_iter().map(UserDto::from).collect();

    Ok(PaginatedResponse::Page(PageResponse {
      data: items,
      meta: PageMeta {
        total,
        page,
        per_page,
        total_pages,
      },
    }))
  }
}

pub async fn create(
  db: &DatabaseConnection,
  cfg: &Config,
  email: String,
  password: String,
  name: String,
) -> Result<UserDto, ApiError> {
  // Hash password
  let password_hash = hash(password.as_bytes(), cfg.bcrypt_cost)
    .map_err(|e| ApiError::InternalError(anyhow::anyhow!("Failed to hash password: {}", e)))?;

  let user = entities::ActiveModel {
    id: Set(Uuid::new_v4()),
    email: Set(email),
    password: Set(password_hash),
    name: Set(name),
    status: Set(UserStatus::Active),
    ..Default::default()
  };

  let user = user.insert(db).await.map_err(|e| {
    if e.to_string().contains("duplicate key") {
      ApiError::InvalidRequest("Email already exists".to_string())
    } else {
      ApiError::InternalError(anyhow::anyhow!(e))
    }
  })?;

  Ok(UserDto::from(user))
}

pub async fn show(db: &DatabaseConnection, id: Uuid) -> Result<UserDto, ApiError> {
  let user = UserEntity::find_by_id(id)
    .into_partial_model::<UserProfile>()
    .one(db)
    .await?
    .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

  Ok(UserDto::from(user))
}

pub async fn update(db: &DatabaseConnection, id: Uuid, name: String) -> Result<UserDto, ApiError> {
  let user = UserEntity::find_by_id(id)
    .one(db)
    .await?
    .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

  let mut user: entities::ActiveModel = user.into();
  user.name = Set(name);

  let user = user.update(db).await?;
  Ok(UserDto::from(user))
}

pub async fn destroy(db: &DatabaseConnection, id: Uuid) -> Result<(), ApiError> {
  let user = UserEntity::find_by_id(id)
    .one(db)
    .await?
    .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

  let user: entities::ActiveModel = user.into();
  user.delete(db).await?;
  Ok(())
}
