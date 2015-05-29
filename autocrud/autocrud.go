package autocrud

import (
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/unverschaemt/gobscene/ginutil"
	"gopkg.in/mgo.v2/bson"
	"log"
	"net/http"
	"reflect"
)

type crudModel struct {
	collectionName string
	modelType      reflect.Type
}

func Crud(r *gin.RouterGroup, model interface{}, collectionName string) {
	modelType := reflect.TypeOf(model)
	/*	log.Printf("autocrud: model type: %v", modelType)
		modelPt := reflect.New(modelType)
		log.Printf("autocrud: model has type: %v", modelPt)
		models := reflect.New(reflect.SliceOf(modelType))
		log.Printf("autocrud: model slice: %v", models)*/
	if modelType.Kind() == reflect.Struct {
		cm := crudModel{collectionName, modelType}
		{
			r.GET("", cm.listModel)
			r.GET("/:id", cm.takeModel)
			r.POST("", cm.createModel)
			r.DELETE("/:id", cm.deleteModel)
			r.PUT("/:id", cm.updateModel)
		}
	} else {
		log.Panicf("autocrud: expected struct, but got %v", modelType.Kind())
	}
}

// returns all modules in collection, limit 50
func (cm *crudModel) listModel(c *gin.Context) {
	modelSlice := reflect.New(reflect.SliceOf(cm.modelType))

	err := ginutil.GetDB(c).C("modules").Find(nil).Limit(50).All(modelSlice.Interface())
	if err != nil {
		c.String(http.StatusBadRequest, err.Error())
	}
	c.JSON(http.StatusOK, modelSlice.Elem().Interface())

}

func (cm *crudModel) takeModel(c *gin.Context) {
	model := reflect.New(cm.modelType)
	id := bson.ObjectIdHex(c.Params.ByName("id"))
	if !id.Valid() {
		c.String(http.StatusBadRequest, "id is not a valid ObjectId")
		c.Abort()
	}
	err := ginutil.GetDB(c).C(cm.collectionName).FindId(id).One(model.Interface())
	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusNotFound)
	} else {
		log.Println(model.Elem().Interface())
		c.JSON(http.StatusOK, model.Elem().Interface())
	}
}

/*
createModel()
*/
func (cm *crudModel) createModel(c *gin.Context) {
	if c.Request.Header.Get("Content-Type") == "application/json" {
		model := reflect.New(cm.modelType)
		if c.BindWith(model.Interface(), binding.JSON) {
			// mv = the direct value of model
			mv := model.Elem()
			// create a new id
			id := bson.NewObjectId()
			// set the ObjectId
			mv.FieldByName("Id").Set(reflect.ValueOf(id))
			// mv.Interface() "removes" reflection
			err := ginutil.GetDB(c).C("modules").Insert(mv.Interface())
			if err != nil {
				log.Panicln(err)
			}
			c.String(http.StatusCreated, id.Hex())
		}
	} else {
		c.String(http.StatusBadRequest, "Content-Type must be application/json")
	}
}

func (cm *crudModel) updateModel(c *gin.Context) {
	id := c.Params.ByName("id")
	model := reflect.New(cm.modelType)
	if c.BindWith(model.Interface(), binding.JSON) {
		log.Println(model.Elem().Interface())
		err := ginutil.GetDB(c).C("modules").UpdateId(bson.ObjectIdHex(id), model.Elem().Interface())
		if err != nil {
			log.Panicln(err)
		}
		c.String(http.StatusOK, "Added")
	}
}

func (cm *crudModel) deleteModel(c *gin.Context) {
	id := c.Params.ByName("id")
	err := ginutil.GetDB(c).C(cm.collectionName).RemoveId(bson.ObjectIdHex(id))
	if err != nil {
		log.Panicln(err)
	}
	c.String(http.StatusOK, "Deleted")
}
