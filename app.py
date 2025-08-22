# ... rest of the code ...

@app.route('/admin/edit-album/<int:album_id>', methods=['GET', 'POST'])
def edit_album(album_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    albums = load_data(app.config['ALBUMS_FILE'])
    album = next((a for a in albums if a['id'] == album_id), None)
    
    if not album:
        flash('Album not found', 'danger')
        return redirect(url_for('manage_albums'))
    
    if request.method == 'POST':
        try:
            if not validate_csrf_token():
                flash('Security token invalid. Please try again.', 'danger')
                return render_template('admin/edit_album.html', album=album, csrf_token=generate_csrf_token())
            
            # Update album data
            album_index = next((i for i, a in enumerate(albums) if a['id'] == album_id), -1)
            
            if album_index != -1:
                # Handle new cover upload if provided
                cover = request.files.get('cover')
                if cover and cover.filename:
                    if allowed_file(cover.filename, 'image') and allowed_file_size(cover):
                        # Remove old cover
                        old_cover_path = os.path.join('static', albums[album_index]['cover'])
                        if os.path.exists(old_cover_path) and is_safe_path('static/uploads', old_cover_path):
                            os.remove(old_cover_path)
                        
                        # Save new cover
                        filename = secure_filename(cover.filename)
                        cover_path = os.path.join(app.config['COVERS_FOLDER'], filename)
                        cover.save(cover_path)
                        
                        # Simplified image validation
                        if os.path.exists(cover_path) and is_safe_path(app.config['COVERS_FOLDER'], cover_path):
                            albums[album_index]['cover'] = os.path.join('uploads', 'covers', filename).replace('\\', '/')
                        else:
                            if os.path.exists(cover_path):
                                os.remove(cover_path)
                            flash('Invalid image file', 'danger')
                    else:
                        flash('Invalid cover image type or file too large', 'danger')
                
                # Handle new video upload if provided
                video_file = request.files.get('video_file')
                video_category = request.form.get('video_category', 'music_videos')
                if video_file and video_file.filename:
                    if allowed_video_file(video_file.filename) and allowed_file_size(video_file, app.config['MAX_VIDEO_SIZE']):
                        # Remove old video if exists
                        if albums[album_index].get('video_filename'):
                            old_video_category = albums[album_index].get('video_category', 'music_videos')
                            old_video_path = os.path.join(app.config['VIDEOS_FOLDER'], old_video_category, albums[album_index]['video_filename'])
                            if os.path.exists(old_video_path) and is_safe_path(app.config['VIDEOS_FOLDER'], old_video_path):
                                os.remove(old_video_path)
                        
                        # Create category directory if it doesn't exist
                        category_dir = os.path.join(app.config['VIDEOS_FOLDER'], video_category)
                        os.makedirs(category_dir, exist_ok=True)
                        
                        # Save new video
                        video_filename = secure_filename(f"{int(time.time())}_{video_file.filename}")
                        video_path = os.path.join(category_dir, video_filename)
                        video_file.save(video_path)
                        
                        if is_safe_path(app.config['VIDEOS_FOLDER'], video_path):
                            albums[album_index]['video_filename'] = video_filename
                            albums[album_index]['video_category'] = video_category
                            albums[album_index]['has_video'] = True
                        else:
                            os.remove(video_path)
                            flash('Invalid video file path', 'danger')
                    else:  # This else was incorrectly indented in the original code
                        flash(f'Invalid video file type or file too large (max {app.config["MAX_VIDEO_SIZE"] // (1024*1024)}MB)', 'danger')
                
                # Update other fields
                albums[album_index]['title'] = escape(request.form.get('title', '').strip())
                albums[album_index]['artist'] = escape(request.form.get('artist', '').strip())
                albums[album_index]['year'] = escape(request.form.get('year', '').strip())
                albums[album_index]['price'] = round(float(request.form.get('price', 0)), 2)
                albums[album_index]['on_sale'] = 'on_sale' in request.form
                albums[album_index]['sale_price'] = round(float(request.form.get('sale_price', 0)), 2) if request.form.get('sale_price') else None
                
                # Remove video if requested
                if 'remove_video' in request.form:
                    if albums[album_index].get('video_filename'):
                        video_category = albums[album_index].get('video_category', 'music_videos')
                        video_path = os.path.join(app.config['VIDEOS_FOLDER'], video_category, albums[album_index]['video_filename'])
                        if os.path.exists(video_path) and is_safe_path(app.config['VIDEOS_FOLDER'], video_path):
                            os.remove(video_path)
                    albums[album_index]['video_filename'] = None
                    albums[album_index]['video_category'] = None
                    albums[album_index]['has_video'] = False
                
                if save_data(albums, app.config['ALBUMS_FILE']):
                    flash('Album updated successfully', 'success')
                    log_security_event('ALBUM_UPDATED', f'Album ID: {album_id}')
                    return redirect(url_for('manage_albums'))
                else:
                    flash('Failed to update album', 'danger')
            else:
                flash('Album not found in database', 'danger')
            
        except ValueError:
            flash('Invalid price format', 'danger')
        except Exception as e:
            logger.error(f"Edit album error: {e}")
            log_security_event('ALBUM_UPDATE_ERROR', f'Album ID: {album_id}, Error: {str(e)}')
            flash('Error updating album', 'danger')
    
    return render_template('admin/edit_album.html', album=album, csrf_token=generate_csrf_token())

# ... rest of the code ...
