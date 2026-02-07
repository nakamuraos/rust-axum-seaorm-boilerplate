use bcrypt::hash;
use sea_orm::{
  ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
  QueryOrder, QuerySelect, Set,
};
use uuid::Uuid;

use crate::common::api_error::ApiError;
use crate::common::cfg::Config;
use crate::common::pagination::{
  CursorMeta, CursorResponse, PageMeta, PageResponse, PaginatedResponse, PaginationParams,
};
use crate::modules::users::dto::UserDto;
use crate::modules::users::entities::{self, Entity as UserEntity};
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

    // Find cursor item to get its created_at
    let cursor_item = UserEntity::find()
      .filter(entities::Column::Id.eq(cursor_id))
      .one(db)
      .await?
      .ok_or_else(|| ApiError::InvalidRequest("Cursor not found".to_string()))?;

    // Fetch items after cursor: (created_at, id) > (cursor_created_at, cursor_id)
    // Order by created_at ASC, id ASC for stable ordering
    let users = UserEntity::find()
      .filter(
        sea_orm::Condition::any()
          .add(entities::Column::CreatedAt.gt(cursor_item.created_at))
          .add(
            sea_orm::Condition::all()
              .add(entities::Column::CreatedAt.eq(cursor_item.created_at))
              .add(entities::Column::Id.gt(cursor_id)),
          ),
      )
      .order_by_asc(entities::Column::CreatedAt)
      .order_by_asc(entities::Column::Id)
      .limit(per_page + 1)
      .all(db)
      .await?;

    // Take per_page + 1 to determine if there's a next page
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

    let query = UserEntity::find()
      .order_by_asc(entities::Column::CreatedAt)
      .order_by_asc(entities::Column::Id);

    let paginator = query.paginate(db, per_page);
    let total = paginator.num_items().await?;
    let total_pages = (total + per_page - 1) / per_page;
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
  let user = UserEntity::find()
    .filter(entities::Column::Id.eq(id))
    .one(db)
    .await?
    .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

  Ok(UserDto::from(user))
}

pub async fn update(db: &DatabaseConnection, id: Uuid, name: String) -> Result<UserDto, ApiError> {
  let user = UserEntity::find()
    .filter(entities::Column::Id.eq(id))
    .one(db)
    .await?
    .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

  let mut user: entities::ActiveModel = user.into();
  user.name = Set(name);

  let user = user.update(db).await?;
  Ok(UserDto::from(user))
}

pub async fn destroy(db: &DatabaseConnection, id: Uuid) -> Result<(), ApiError> {
  let user = UserEntity::find()
    .filter(entities::Column::Id.eq(id))
    .one(db)
    .await?
    .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

  let user: entities::ActiveModel = user.into();
  user.delete(db).await?;
  Ok(())
}
